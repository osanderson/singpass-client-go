package singpasstest

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"slices"
	"sync"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// registry holds the registered clients and serves the lookups FAPIgo's
// server needs: the client record, its client-assertion verification key and
// its id_token / userinfo encryption key.
type registry struct {
	mu      sync.RWMutex
	clients map[fapi.ClientID]registeredClient
}

type registeredClient struct {
	cfg    Client
	stored storage.RegisteredClient
	encKey *ecdh.PublicKey
}

func newRegistry() *registry {
	return &registry{clients: make(map[fapi.ClientID]registeredClient)}
}

func (r *registry) add(c registeredClient) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[c.stored.ID()] = c
}

func (r *registry) get(id fapi.ClientID) (registeredClient, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[id]
	return c, ok
}

// ids returns the registered client IDs, sorted.
func (r *registry) ids() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.clients))
	for id := range r.clients {
		ids = append(ids, string(id))
	}
	slices.Sort(ids)
	return ids
}

// ResolveClient implements storage.ClientRepository.
func (r *registry) ResolveClient(_ context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	c, ok := r.get(id)
	if !ok {
		return storage.RegisteredClient{}, fmt.Errorf("singpasstest: unknown client %q", id)
	}
	return c.stored, nil
}

// ResolveVerificationKeys implements keys.ClientKeySource: the client's
// registered signing key verifies its private_key_jwt client assertions.
func (r *registry) ResolveVerificationKeys(_ context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	c, ok := r.get(req.ClientID)
	if !ok {
		return keys.VerificationKeySet{}, fmt.Errorf("singpasstest: unknown client %q", req.ClientID)
	}
	if req.Purpose != keys.ClientAssertionVerification {
		return keys.VerificationKeySet{}, fmt.Errorf("singpasstest: unsupported verification purpose %v", req.Purpose)
	}
	return keys.VerificationKeySet{Keys: []keys.VerificationKey{
		{KeyID: c.cfg.SigningKID, Algorithm: req.Algorithm, PublicKey: c.cfg.SigningKey},
	}}, nil
}

// ResolveEncryptionKeys implements keys.ClientEncryptionKeySource: the client's
// registered encryption key receives both the id_token and /userinfo JWEs.
func (r *registry) ResolveEncryptionKeys(_ context.Context, req keys.ClientEncryptionKeyRequest) (keys.ClientEncryptionKeySet, error) {
	c, ok := r.get(req.ClientID)
	if !ok {
		return keys.ClientEncryptionKeySet{}, fmt.Errorf("singpasstest: unknown client %q", req.ClientID)
	}
	return keys.ClientEncryptionKeySet{Keys: []keys.ClientEncryptionKey{
		{KeyID: c.cfg.EncryptionKID, Algorithm: req.Algorithm, PublicKey: c.encKey},
	}}, nil
}
