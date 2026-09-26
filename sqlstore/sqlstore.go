// Package sqlstore is a durable, SQL-backed session store for production:
// it implements both the protocol session store (singpass.SessionStore, for
// Dependencies.Sessions) and the web helper's login-session store
// (web.LoginSessionStore, for web.Config.LoginSessions).
//
// It uses database/sql only, so it adds no dependencies: bring your own driver
// for Postgres, MySQL or SQLite. Every instance of the app shares the database,
// so a login can start on one instance and finish on another.
//
//	db, _ := sql.Open("pgx", os.Getenv("DATABASE_URL"))
//	store := sqlstore.New(db, sqlstore.Config{Dialect: sqlstore.Postgres})
//	if err := store.CreateTables(ctx); err != nil { … }
//
//	client, _ := singpass.NewMyinfo(ctx, singpass.MyinfoOptions{
//		Environment: singpass.Production, …
//	}, singpass.Dependencies{Sessions: store.Sessions()})
//	h := web.New(web.Config{LoginSessions: store.LoginSessions(), …})
//
// Expired rows are ignored when read but not deleted automatically; call
// DeleteExpired periodically (e.g. every few minutes) to keep the tables small.
package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	singpass "github.com/osanderson/singpass-client-go"
	"github.com/osanderson/singpass-client-go/web"

	"github.com/idfoundry/fapigo/storage"
)

// Dialect selects SQL syntax: placeholders and column types.
type Dialect int

const (
	// Postgres uses $1-style placeholders.
	Postgres Dialect = iota
	// MySQL (and MariaDB) use ? placeholders and MEDIUMTEXT for identities,
	// which can exceed TEXT's 64 KB with large Myinfo responses.
	MySQL
	// SQLite uses ? placeholders.
	SQLite
)

// Config configures a Store.
type Config struct {
	Dialect Dialect
	// TablePrefix is prepended to the two table names ("<prefix>auth_sessions"
	// and "<prefix>login_sessions"). Empty means "singpass_". Letters, digits
	// and underscores only.
	TablePrefix string
	// Now returns the current time; nil means time.Now. For tests.
	Now func() time.Time
}

// Store holds the two session tables. Build it with New and create the tables
// with CreateTables (or your own migration using the same schema).
type Store struct {
	db      *sql.DB
	dialect Dialect
	auth    string // protocol sessions table
	login   string // login sessions table
	now     func() time.Time
}

var validPrefix = regexp.MustCompile(`^[A-Za-z0-9_]*$`)

// New returns a Store over db. It panics if cfg.TablePrefix isn't a plain
// identifier, since the prefix is written into SQL.
func New(db *sql.DB, cfg Config) *Store {
	prefix := cfg.TablePrefix
	if prefix == "" {
		prefix = "singpass_"
	}
	if !validPrefix.MatchString(prefix) {
		panic(fmt.Sprintf("sqlstore: invalid table prefix %q", prefix))
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, dialect: cfg.Dialect, auth: prefix + "auth_sessions", login: prefix + "login_sessions", now: now}
}

// ph returns the n-th (1-based) placeholder for the dialect.
func (s *Store) ph(n int) string {
	if s.dialect == Postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// q replaces ? placeholders in query with the dialect's.
func (s *Store) q(query string) string {
	if s.dialect != Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString(s.ph(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// CreateTables creates the two tables and their expiry indexes if they don't
// exist. The schema is simple enough to copy into your own migrations instead.
func (s *Store) CreateTables(ctx context.Context) error {
	blob := "TEXT"
	if s.dialect == MySQL {
		blob = "MEDIUMTEXT" // large Myinfo responses can exceed TEXT's 64 KB
	}
	tables := []struct{ name, columns string }{
		{s.auth, `state VARCHAR(255) NOT NULL PRIMARY KEY,
			nonce VARCHAR(255) NOT NULL,
			pkce_verifier VARCHAR(255) NOT NULL,
			expected_issuer VARCHAR(2048) NOT NULL,
			expected_redirect_uri VARCHAR(2048) NOT NULL,
			expected_response_mode VARCHAR(64) NOT NULL,
			expires_at BIGINT NOT NULL`}, // Unix nanoseconds
		{s.login, `sid VARCHAR(64) NOT NULL PRIMARY KEY,
			identity ` + blob + ` NOT NULL,
			expires_at BIGINT NOT NULL`},
	}
	for _, t := range tables {
		index := t.name + "_expires"
		var stmts []string
		if s.dialect == MySQL {
			// MySQL has no CREATE INDEX IF NOT EXISTS, so declare it inline.
			stmts = []string{`CREATE TABLE IF NOT EXISTS ` + t.name + ` (` + t.columns + `, INDEX ` + index + ` (expires_at))`}
		} else {
			stmts = []string{
				`CREATE TABLE IF NOT EXISTS ` + t.name + ` (` + t.columns + `)`,
				`CREATE INDEX IF NOT EXISTS ` + index + ` ON ` + t.name + ` (expires_at)`,
			}
		}
		for _, stmt := range stmts {
			if _, err := s.db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("sqlstore: create tables: %w", err)
			}
		}
	}
	return nil
}

// DeleteExpired removes expired rows from both tables and returns how many it
// removed. Run it periodically.
func (s *Store) DeleteExpired(ctx context.Context) (int64, error) {
	now := s.now().UnixNano()
	var total int64
	for _, table := range []string{s.auth, s.login} {
		res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+table+` WHERE expires_at <= ?`), now)
		if err != nil {
			return total, fmt.Errorf("sqlstore: delete expired: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// Sessions returns the protocol session store for singpass.Dependencies.Sessions.
// It is durable and consumes atomically, so it satisfies AssuranceProduction.
func (s *Store) Sessions() singpass.SessionStore { return authSessions{s} }

// LoginSessions returns the login-session store for web.Config.LoginSessions.
func (s *Store) LoginSessions() web.LoginSessionStore { return loginSessions{s} }

type authSessions struct{ s *Store }

// Capabilities implements singpass.StoreAssurance.
func (authSessions) Capabilities() storage.Capabilities {
	return storage.Capabilities{Durable: true, AtomicConsume: true}
}

func (a authSessions) Create(ctx context.Context, n storage.NewSession) error {
	_, err := a.s.db.ExecContext(ctx, a.s.q(`INSERT INTO `+a.s.auth+
		` (state, nonce, pkce_verifier, expected_issuer, expected_redirect_uri, expected_response_mode, expires_at)
		  VALUES (?, ?, ?, ?, ?, ?, ?)`),
		n.State, n.Nonce, n.PKCEVerifier, n.ExpectedIssuer, n.ExpectedRedirectURI, n.ExpectedResponseMode, n.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sqlstore: create session: %w", err)
	}
	return nil
}

// Consume reads the session and deletes it; only the caller whose DELETE
// removes the row wins, so concurrent consumes of one state have exactly one
// winner on every dialect (no RETURNING needed). Unknown, used or expired
// states report singpass.ErrLoginExpired.
func (a authSessions) Consume(ctx context.Context, c storage.SessionConsumption) (storage.ConsumedSession, error) {
	var (
		out       storage.ConsumedSession
		expiresNs int64
	)
	err := a.s.db.QueryRowContext(ctx, a.s.q(`SELECT nonce, pkce_verifier, expected_issuer, expected_redirect_uri, expected_response_mode, expires_at
		FROM `+a.s.auth+` WHERE state = ?`), c.State).
		Scan(&out.Nonce, &out.PKCEVerifier, &out.ExpectedIssuer, &out.ExpectedRedirectURI, &out.ExpectedResponseMode, &expiresNs)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ConsumedSession{}, singpass.ErrLoginExpired
	}
	if err != nil {
		return storage.ConsumedSession{}, fmt.Errorf("sqlstore: read session: %w", err)
	}
	res, err := a.s.db.ExecContext(ctx, a.s.q(`DELETE FROM `+a.s.auth+` WHERE state = ?`), c.State)
	if err != nil {
		return storage.ConsumedSession{}, fmt.Errorf("sqlstore: consume session: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return storage.ConsumedSession{}, fmt.Errorf("sqlstore: consume session: %w", err)
	} else if n != 1 {
		return storage.ConsumedSession{}, singpass.ErrLoginExpired // another caller consumed it first
	}
	out.ExpiresAt = time.Unix(0, expiresNs)
	if !a.s.now().Before(out.ExpiresAt) {
		return storage.ConsumedSession{}, singpass.ErrLoginExpired
	}
	return out, nil
}

type loginSessions struct{ s *Store }

func (l loginSessions) Create(ctx context.Context, id *singpass.Identity, ttl time.Duration) (string, error) {
	data, err := json.Marshal(id)
	if err != nil {
		return "", fmt.Errorf("sqlstore: encode identity: %w", err)
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	sid := base64.RawURLEncoding.EncodeToString(b[:])
	if _, err := l.s.db.ExecContext(ctx, l.s.q(`INSERT INTO `+l.s.login+` (sid, identity, expires_at) VALUES (?, ?, ?)`),
		sid, string(data), l.s.now().Add(ttl).UnixNano()); err != nil {
		return "", fmt.Errorf("sqlstore: create login session: %w", err)
	}
	return sid, nil
}

func (l loginSessions) Get(ctx context.Context, sid string) (*singpass.Identity, bool, error) {
	var data string
	err := l.s.db.QueryRowContext(ctx, l.s.q(`SELECT identity FROM `+l.s.login+` WHERE sid = ? AND expires_at > ?`),
		sid, l.s.now().UnixNano()).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("sqlstore: read login session: %w", err)
	}
	var id singpass.Identity
	if err := json.Unmarshal([]byte(data), &id); err != nil {
		return nil, false, fmt.Errorf("sqlstore: decode identity: %w", err)
	}
	return &id, true, nil
}

func (l loginSessions) Delete(ctx context.Context, sid string) error {
	if _, err := l.s.db.ExecContext(ctx, l.s.q(`DELETE FROM `+l.s.login+` WHERE sid = ?`), sid); err != nil {
		return fmt.Errorf("sqlstore: delete login session: %w", err)
	}
	return nil
}
