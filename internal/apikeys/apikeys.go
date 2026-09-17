// Package apikeys mints, parses, and verifies client API keys. It is
// deliberately framework-free (no web-framework imports) so it is
// independently unit-testable and fuzzable; the HTTP-facing decisions (which
// problem code to return, when to consult the registry) live in the auth
// middleware.
//
// Key shape: "vk_<prefix>_<secret>". prefix is an 8-char Crockford-base32
// public lookup id (stored in the clear, indexed); secret is 32 base64url
// chars (192 bits of entropy) the client must keep. Only the argon2id PHC
// hash of secret is ever persisted — Mint returns the plaintext secret
// exactly once, at creation time.
package apikeys

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters: OWASP Password Storage Cheat Sheet's SECOND
// recommended configuration (m=19 MiB, t=2, p=1, 128-bit salt, 256-bit tag).
// The centralized crypto policy (ECCG-pinned allow-lists) governs JOSE/COSE
// signing and encryption algorithms; argon2id is a password-style KDF for
// hash-at-rest, not a signing/verification algorithm, so
// golang.org/x/crypto/argon2 is used directly here.
const (
	argonMemoryKiB = 19456 // 19 MiB
	argonTime      = 2
	argonThreads   = 1
	argonVersion   = argon2.Version // 0x13 == 19

	saltLen = 16 // bytes
	tagLen  = 32 // bytes

	prefixRawLen = 5  // bytes of randomness -> 8 crockford32 chars (40 bits / 5 bits-per-char)
	prefixLen    = 8  // encoded chars
	secretRawLen = 24 // bytes of randomness (192 bits) -> 32 base64url chars
	secretLen    = 32 // encoded chars

	keyScheme = "vk"
)

// crockford32 is Crockford's Base32 alphabet (excludes I, L, O, U to avoid
// visual ambiguity with 1/0) — used only for the public, non-secret
// key-lookup prefix, never for the secret itself.
var crockford32 = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// ErrFormat is returned by Parse for any malformed presented key. It never
// wraps or otherwise carries the offending input — an error string built
// from attacker/secret-derived data would be a logging hazard the moment a
// caller does the natural thing and logs the error.
var ErrFormat = errors.New("apikeys: malformed key")

// errPHCFormat is decodePHC's parse failure. Internal: a stored PHC hash is
// never attacker-controlled (it comes from the registry, not the request), so
// this does not need ErrFormat's "never carry the input" discipline, but it
// still never includes the hash itself (defense in depth).
var errPHCFormat = errors.New("apikeys: malformed PHC hash")

// Mint generates a fresh API key: a public prefix (safe to store/log/index)
// and a secret (returned to the caller exactly once, never stored), plus the
// argon2id PHC hash of the secret — the only thing the caller should persist.
// r is the randomness source (crypto/rand.Reader in production; a
// deterministic reader in tests that need reproducible fixtures).
func Mint(r io.Reader) (displayKey, prefix, phcHash string, err error) {
	prefixRaw := make([]byte, prefixRawLen)
	if _, err := io.ReadFull(r, prefixRaw); err != nil {
		return "", "", "", fmt.Errorf("apikeys: mint prefix: %w", err)
	}
	prefix = crockford32.EncodeToString(prefixRaw)

	secretRaw := make([]byte, secretRawLen)
	if _, err := io.ReadFull(r, secretRaw); err != nil {
		return "", "", "", fmt.Errorf("apikeys: mint secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretRaw)

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r, salt); err != nil {
		return "", "", "", fmt.Errorf("apikeys: mint salt: %w", err)
	}
	tag := argon2.IDKey([]byte(secret), salt, argonTime, argonMemoryKiB, argonThreads, tagLen)

	return keyScheme + "_" + prefix + "_" + secret, prefix, encodePHC(salt, tag), nil
}

// Parse splits a presented API key of the form "vk_<prefix>_<secret>" into
// its prefix and secret. It never panics on malformed input (see
// FuzzParseAPIKey) and never echoes the input back in an error (see
// ErrFormat).
//
// SplitN(…, "_", 3) rather than Split: the secret is base64url, whose
// alphabet legally contains '_', so a naive split-and-count-parts on every
// underscore would misparse a well-formed key whose secret happens to
// contain one. Capping at 3 parts makes the split unambiguous regardless of
// what characters appear inside the secret.
func Parse(presented string) (prefix, secret string, err error) {
	parts := strings.SplitN(presented, "_", 3)
	if len(parts) != 3 || parts[0] != keyScheme {
		return "", "", ErrFormat
	}

	prefix, secret = parts[1], parts[2]
	if len(prefix) != prefixLen || !isCrockford(prefix) {
		return "", "", ErrFormat
	}
	if len(secret) != secretLen || !isBase64URL(secret) {
		return "", "", ErrFormat
	}

	return prefix, secret, nil
}

func isCrockford(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) {
			return false
		}
	}
	return true
}

func isBase64URL(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// phc is a decoded argon2id PHC hash string.
type phc struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	tag     []byte
}

// encodePHC renders salt/tag into this service's fixed PHC shape:
// $argon2id$v=19$m=19456,t=2,p=1$<salt-b64>$<tag-b64>, using the PHC string
// spec's own base64 convention (standard alphabet, no padding —
// base64.RawStdEncoding).
func encodePHC(salt, tag []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVersion, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(tag))
}

// decodePHC parses a PHC string produced by encodePHC, returning the exact
// params/salt/tag it was minted with — Verify re-derives with THESE params,
// never hardcoded ones, so a future param bump can still verify old hashes.
// Anything that isn't this exact argon2id shape is rejected: an unknown
// algorithm or params set is rejected outright, never allowed to fall through
// to a guess.
func decodePHC(s string) (phc, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return phc{}, errPHCFormat
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return phc{}, errPHCFormat
	}
	if version != argonVersion {
		return phc{}, errPHCFormat
	}

	var mem, t uint32
	var p uint8
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil || n != 3 {
		return phc{}, errPHCFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return phc{}, errPHCFormat
	}
	tag, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return phc{}, errPHCFormat
	}
	// maxDecodedLen is a generous bound on a legitimate salt/tag (encodePHC
	// only ever writes 16/32 bytes) — rejecting anything absurdly large here
	// both fails closed on a corrupt stored hash and keeps the later
	// int->uint32 length conversion in Verify demonstrably in range.
	const maxDecodedLen = 128
	if len(salt) == 0 || len(salt) > maxDecodedLen || len(tag) == 0 || len(tag) > maxDecodedLen {
		return phc{}, errPHCFormat
	}

	return phc{memory: mem, time: t, threads: p, salt: salt, tag: tag}, nil
}

// DummyKeyID is the fixed cache slot the auth middleware uses with DummyPHC
// when a presented key cannot be resolved to a real registry row (malformed
// key or unknown prefix) — see DummyPHC's doc comment for why a real derive
// still has to happen in that case.
const DummyKeyID = "apikeys:dummy"

// dummyPHC is computed once, lazily, from fixed (non-secret) inputs.
var dummyPHC = sync.OnceValue(func() string {
	salt := sha256.Sum256([]byte("apikeys: fixed dummy salt v1 — never a real key"))
	tag := argon2.IDKey([]byte("apikeys: fixed dummy secret v1 — never a real key"),
		salt[:saltLen], argonTime, argonMemoryKiB, argonThreads, tagLen)
	return encodePHC(salt[:saltLen], tag)
})

// DummyPHC returns a fixed, well-formed argon2id PHC hash with no
// corresponding real key. The auth middleware verifies the presented secret
// against it whenever a real hash isn't available (malformed key, unknown
// prefix), so that class of failure pays the exact same argon2id derive cost
// and produces the exact same (bool, error) shape as "wrong secret against a
// real, existing key" — otherwise the mere PRESENCE or ABSENCE of that
// derive (drastically slower than the registry lookup it replaces) would
// itself be a timing oracle letting an attacker enumerate valid key
// prefixes without ever touching the real hash material.
func DummyPHC() string { return dummyPHC() }

// cache tuning: a verified-key cache exists to make steady-state auth O(1)
// for a client re-authenticating with the same CORRECT key many times, not
// to defeat brute forcing (see Verify's doc comment). ONLY successful
// verdicts are ever cached (Verify), so the cap is bounded by the number of
// live, legitimately-authenticating keys — attacker traffic (all failures)
// never populates it, and no failure is ever served fast from cache. 5
// minutes comfortably covers typical client polling intervals; 1024 entries
// covers many times the expected concurrent-client count.
const (
	cacheTTL = 5 * time.Minute
	cacheCap = 1024
)

// cacheEntry records a SUCCESSFUL verification for one (keyID, secret) pair.
// Only successes are ever stored (see Verify), so a live entry whose secret
// hash matches unambiguously means "this secret verified against this key" —
// there is no verdict field, and no negative is ever served from cache.
type cacheEntry struct {
	secretHash [sha256.Size]byte
	expiresAt  time.Time
}

// deriveFn abstracts argon2.IDKey. The zero-value Verifier is unusable;
// NewVerifier wires the real function. Same-package white-box tests
// (apikeys_test.go) overwrite it with a counting wrapper around the real
// derive to prove the cache skips it on a hit (TestCacheSkipsArgon2OnHit).
type deriveFn func(secret, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

// Verifier re-derives argon2id over a presented secret and compares it to a
// stored PHC hash with crypto/subtle.ConstantTimeCompare, backed by a small
// in-memory SUCCESS cache keyed by keyID (see cacheTTL/cacheCap).
//
// No early-exit timing oracle: the cache holds ONLY successful verdicts, so
// EVERY failing verify — wrong secret on a known prefix, unknown prefix,
// malformed key — always runs the full argon2id derive-then-compare and
// never short-circuits to a cached negative. Only a
// legitimate client presenting the correct secret ever takes the fast cache
// path. That is what keeps "wrong secret on a known prefix" and "unknown
// prefix" timing-indistinguishable (both always derive): caching failures
// would have made a repeated wrong-secret guess on a dedicated real-key slot
// fast while an unknown prefix — sharing one evictable dummy slot — kept
// re-deriving, a network-measurable prefix-existence oracle. All of this
// holds regardless of whether phcHash is a real stored hash or DummyPHC(),
// and whether secret is a genuine guess or a malformed key's raw bytes. The
// ONLY path that returns a non-nil error is a malformed phcHash string —
// which callers only ever pass a well-formed one
// to (their own PHC string, or the package's own DummyPHC()) — so in
// practice every failure a caller can attacker-trigger returns (false, nil),
// never distinguishing "wrong secret" from "unknown key" by error shape
// either.
type Verifier struct {
	now    func() time.Time
	derive deriveFn

	mu    sync.Mutex
	cache map[string]cacheEntry
	order []string // insertion order, oldest first, for cacheCap eviction
}

// NewVerifier returns a Verifier using now for cache-entry expiry (inject
// time.Now in production; a fixed/advanceable clock in tests).
func NewVerifier(now func() time.Time) *Verifier {
	return &Verifier{
		now:    now,
		derive: argon2.IDKey,
		cache:  make(map[string]cacheEntry),
	}
}

// Verify reports whether secret matches the argon2id hash encoded in
// phcHash. keyID only scopes the verified-key cache (any stable string —
// the registry key id, or DummyKeyID for the no-real-key case); it is never
// compared against secret-derived data and callers must never log it as
// though it were secret (it isn't — it identifies the row, not the key).
func (v *Verifier) Verify(keyID, phcHash, secret string) (bool, error) {
	secretHash := sha256.Sum256([]byte(secret))
	now := v.now()

	if v.cacheLookup(keyID, secretHash, now) {
		return true, nil // a cache hit is, by construction, a prior success
	}

	p, err := decodePHC(phcHash)
	if err != nil {
		return false, err
	}
	tag := v.derive([]byte(secret), p.salt, p.time, p.memory, p.threads, uint32(len(p.tag))) // #nosec G115 -- decodePHC bounds len(p.tag) <= maxDecodedLen
	ok := subtle.ConstantTimeCompare(tag, p.tag) == 1

	// Cache ONLY successes: a cached negative would turn a repeated
	// wrong-secret guess on a real key's dedicated slot into a fast path while
	// an unknown prefix — sharing one evictable dummy slot — kept re-deriving,
	// leaking prefix existence via timing. Failures always re-derive.
	if ok {
		v.cacheStore(keyID, secretHash, now)
	}

	return ok, nil
}

// cacheLookup reports whether keyID has a live cached SUCCESS whose secret
// hash matches secretHash. The hash comparison is constant-time (a cached
// success for one secret must not be distinguishable, timing-wise, from a
// miss for another). Only successes are ever stored (Verify), so a true
// result unambiguously means "verified" — there is no cached negative to
// serve, which is the whole point of the no-negative-cache rule.
func (v *Verifier) cacheLookup(keyID string, secretHash [sha256.Size]byte, now time.Time) bool {
	v.mu.Lock()
	entry, exists := v.cache[keyID]
	v.mu.Unlock()

	if !exists || now.After(entry.expiresAt) {
		return false
	}
	// A live entry exists but for a DIFFERENT secret (the key was rotated, or
	// this is a guess against a slot warmed by the real secret) — miss, so the
	// caller falls through to a full cold verify.
	return subtle.ConstantTimeCompare(entry.secretHash[:], secretHash[:]) == 1
}

// cacheStore records a successful (keyID, secretHash) verification, evicting
// the oldest entry first if the cache is at cacheCap and keyID is new. Called
// only on the success path (Verify).
func (v *Verifier) cacheStore(keyID string, secretHash [sha256.Size]byte, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, exists := v.cache[keyID]; !exists {
		if len(v.order) >= cacheCap {
			delete(v.cache, v.order[0])
			v.order = v.order[1:]
		}
		v.order = append(v.order, keyID)
	}
	v.cache[keyID] = cacheEntry{secretHash: secretHash, expiresAt: now.Add(cacheTTL)}
}
