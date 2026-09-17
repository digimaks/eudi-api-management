package registrydb

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Fake is the in-memory Store for unit tests. It mirrors procedure
// semantics: client isolation is enforced on every call (wrong client_id ->
// registry:not_found, no existence leak), a revoked intended use is rejected
// at template-create time, WRPRC absence is success-with-nil (never an
// error), and a soft-deleted or another client's template both read as
// not_found.
type Fake struct {
	mu           sync.Mutex
	clients      map[string]*Client
	intendedUses map[string]map[string]*IntendedUse // clientID -> intendedUseID -> row
	templates    map[string]*fakeTemplate           // templateID -> row
	apiKeys      map[string]*fakeAPIKey             // keyID -> row
	keysByPrefix map[string]string                  // prefix -> keyID
	wrprcs       map[string][]byte                  // "clientID|intendedUseID" -> raw bytes (test-only seam)
	seq          int
}

type fakeTemplate struct {
	Template
	ClientID string
	Deleted  bool
}

type fakeAPIKey struct {
	APIKeyRecord
}

// NewFake returns an empty in-memory Store.
func NewFake() *Fake {
	return &Fake{
		clients:      map[string]*Client{},
		intendedUses: map[string]map[string]*IntendedUse{},
		templates:    map[string]*fakeTemplate{},
		apiKeys:      map[string]*fakeAPIKey{},
		keysByPrefix: map[string]string{},
		wrprcs:       map[string][]byte{},
	}
}

// nextID mints a fake 26-char ULID-shaped id — uniqueness is all that
// matters for the fake, not real ULID monotonicity.
func (f *Fake) nextID() string {
	f.seq++
	return fmt.Sprintf("01JZXFAKE%017d", f.seq)
}

// GetClientByKeyPrefix resolves a key prefix, or registry:not_found (404).
func (f *Fake) GetClientByKeyPrefix(_ context.Context, prefix string) (*APIKeyRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	keyID, ok := f.keysByPrefix[prefix]
	if !ok {
		return nil, resultError("registry:not_found")
	}
	k := f.apiKeys[keyID]
	c, ok := f.clients[k.ClientID]
	status := ""
	if ok {
		status = c.Status
	}
	rec := k.APIKeyRecord
	rec.Status = status
	return &rec, nil
}

// GetClient returns a copy of the stored client, or registry:not_found (404).
func (f *Fake) GetClient(_ context.Context, clientID string) (*Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[clientID]
	if !ok {
		return nil, resultError("registry:not_found")
	}
	cp := *c
	return &cp, nil
}

// ListIntendedUses returns every intended use registered for clientID. An
// unknown client yields an empty slice, not an error.
func (f *Fake) ListIntendedUses(_ context.Context, clientID string) ([]IntendedUse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []IntendedUse{}
	for _, iu := range f.intendedUses[clientID] {
		out = append(out, *iu)
	}
	return out, nil
}

// GetIntendedUse returns one intended use scoped to clientID, or
// registry:not_found (404) when absent or owned by another client.
func (f *Fake) GetIntendedUse(_ context.Context, clientID, intendedUseID string) (*IntendedUse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.intendedUses[clientID]
	if !ok {
		return nil, resultError("registry:not_found")
	}
	iu, ok := m[intendedUseID]
	if !ok {
		return nil, resultError("registry:not_found")
	}
	cp := *iu
	return &cp, nil
}

// GetWRPRCForIntendedUse mirrors the procedure's two distinct absent cases:
// an intended use not owned by / unknown to this client -> registry:not_found
// error (no existence leak); an OWNED intended use with no current WRPRC ->
// (nil, nil) success (graceful fallback, never an error).
func (f *Fake) GetWRPRCForIntendedUse(_ context.Context, clientID, intendedUseID string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.intendedUses[clientID]
	if !ok {
		return nil, resultError("registry:not_found")
	}
	if _, ok := m[intendedUseID]; !ok {
		return nil, resultError("registry:not_found")
	}
	raw, ok := f.wrprcs[clientID+"|"+intendedUseID]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), raw...), nil
}

// SeedWRPRC is a test-only seam (NOT part of Store) letting tests exercise
// the "WRPRC present" path. No write path populates WRPRC rows here yet;
// production only ever reads via GetWRPRCForIntendedUse.
func (f *Fake) SeedWRPRC(clientID, intendedUseID string, raw []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wrprcs[clientID+"|"+intendedUseID] = append([]byte(nil), raw...)
}

// CreateTemplate mirrors registry.create_template's up-front validation: the
// intended use must exist for clientID (else registry:not_found) and must not
// be revoked (else registry:intended_use_revoked) before it writes anything.
func (f *Fake) CreateTemplate(_ context.Context, clientID string, t *Template) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.intendedUses[clientID]
	if !ok {
		return "", resultError("registry:not_found")
	}
	iu, ok := m[t.IntendedUseID]
	if !ok {
		return "", resultError("registry:not_found")
	}
	if iu.RevokedAt != "" {
		return "", resultError("registry:intended_use_revoked")
	}

	id := f.nextID()
	now := time.Now().UTC()
	f.templates[id] = &fakeTemplate{
		ClientID: clientID,
		Template: Template{
			ID: id, Name: t.Name, Description: t.Description,
			IntendedUseID: t.IntendedUseID,
			DCQLQuery:     append(json.RawMessage(nil), t.DCQLQuery...),
			CreatedAt:     now,
		},
	}
	t.ID = id
	t.CreatedAt = now
	return id, nil
}

// GetTemplate returns a template scoped to clientID; another client's or a
// soft-deleted template both read as registry:not_found (no existence leak).
func (f *Fake) GetTemplate(_ context.Context, clientID, templateID string) (*Template, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tpl, ok := f.templates[templateID]
	if !ok || tpl.ClientID != clientID || tpl.Deleted {
		return nil, resultError("registry:not_found")
	}
	cp := tpl.Template
	return &cp, nil
}

// ListTemplates returns every non-deleted template owned by clientID.
func (f *Fake) ListTemplates(_ context.Context, clientID string) ([]Template, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Template{}
	for _, tpl := range f.templates {
		if tpl.ClientID == clientID && !tpl.Deleted {
			out = append(out, tpl.Template)
		}
	}
	return out, nil
}

// DeleteTemplate soft-deletes; another client's or an already-deleted
// template both fail with registry:not_found.
func (f *Fake) DeleteTemplate(_ context.Context, clientID, templateID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	tpl, ok := f.templates[templateID]
	if !ok || tpl.ClientID != clientID || tpl.Deleted {
		return resultError("registry:not_found")
	}
	tpl.Deleted = true
	return nil
}

// CreateAPIKey mints a key row; a duplicate prefix mirrors the procedure's
// unique-violation rejection (registry:invalid).
func (f *Fake) CreateAPIKey(_ context.Context, clientID, prefix, secretHash string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.keysByPrefix[prefix]; exists {
		return "", resultError("registry:invalid")
	}
	id := f.nextID()
	f.apiKeys[id] = &fakeAPIKey{APIKeyRecord: APIKeyRecord{
		KeyID: id, ClientID: clientID, SecretHash: secretHash,
	}}
	f.keysByPrefix[prefix] = id
	return id, nil
}

// RevokeAPIKey revokes a key owned by clientID, or registry:not_found (404)
// when keyID belongs to another client or doesn't exist.
func (f *Fake) RevokeAPIKey(_ context.Context, clientID, keyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.apiKeys[keyID]
	if !ok || k.ClientID != clientID {
		return resultError("registry:not_found")
	}
	k.Revoked = true
	return nil
}

// CreateClient inserts a client row (a seed/test/onboarding primitive).
func (f *Fake) CreateClient(_ context.Context, c *Client) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextID()
	cp := *c
	cp.ID = id
	if cp.Status == "" {
		cp.Status = "active"
	}
	if cp.AllowedOrigins == nil {
		cp.AllowedOrigins = []string{}
	}
	if len(cp.Policy) == 0 {
		cp.Policy = json.RawMessage(`{}`)
	}
	f.clients[id] = &cp
	c.ID = id
	return id, nil
}

// SetIntendedUses replaces the full set of intended uses for clientID (a
// seed/test/onboarding primitive) — mirrors the procedure's replace-all
// upsert semantics.
func (f *Fake) SetIntendedUses(_ context.Context, clientID string, ius []IntendedUse) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := make(map[string]*IntendedUse, len(ius))
	for i := range ius {
		iu := ius[i]
		if iu.ID == "" {
			iu.ID = f.nextID()
		}
		m[iu.IntendedUseID] = &iu
	}
	f.intendedUses[clientID] = m
	return nil
}
