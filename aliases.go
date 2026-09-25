package singpass

import (
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// Aliases for the FAPIgo types that appear in this package's API, so a typical
// integration — including a production one — needs only this import. They are
// the same types, not copies: a value of either name is accepted wherever the
// other is expected.

// SessionStore holds in-flight authorization state (state, nonce, PKCE
// verifier) between BeginLogin and Complete: Dependencies.Sessions. Production
// needs a durable implementation that also implements StoreAssurance; verify
// one with FAPIgo's storage.TestSessionStoreContract. Return (or wrap)
// ErrLoginExpired from Consume for an unknown, already-used or expired state.
type SessionStore = storage.SessionStore

// StoreAssurance is how a SessionStore declares it is durable and consumes
// atomically, which AssuranceProduction requires.
type StoreAssurance = storage.StoreAssurance

// AssuranceLevel selects how strictly the client vets its dependencies:
// Dependencies.Assurance.
type AssuranceLevel = client.AssuranceLevel

const (
	// AssuranceDevelopment accepts non-durable stores such as the in-memory
	// default. It is what the zero Dependencies.Assurance selects.
	AssuranceDevelopment = client.AssuranceDevelopment
	// AssuranceProduction refuses a SessionStore that doesn't declare itself
	// durable and atomic, so a deployment can't silently ship the in-memory one.
	AssuranceProduction = client.AssuranceProduction
)

// KeyManager signs client assertions and DPoP proofs: Dependencies.Keys. Build
// one with NewKeyManager.
type KeyManager = keys.KeyManager

// Decrypter decrypts the id_token and /userinfo JWEs: Dependencies.Decryption.
// Build one with NewECDHDecrypter or NewAgreerDecrypter.
type Decrypter = keys.Decrypter

// ECDHAgreer performs the ECDH step of decryption without exposing the private
// key — the seam for an HSM/KMS-held encryption key (LoginOptions.EncryptionAgreer
// and friends, NewAgreerDecrypter).
type ECDHAgreer = keys.ECDHAgreer

// Limits bounds token lifetimes, sizes and timeouts: Dependencies.Limits. See
// RecommendedLimits.
type Limits = client.Limits

// Algorithms is the JOSE algorithm suite: Dependencies.Algorithms. Leave it nil
// for the Singpass/Corppass suite.
type Algorithms = client.Algorithms

// Clock supplies the current time: Dependencies.Clock.
type Clock = client.Clock
