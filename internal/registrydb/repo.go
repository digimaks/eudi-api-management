package registrydb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixed procedure names (see call() in db.go).
const (
	procGetClientByKeyPrefix   = "registry.get_client_by_key_prefix"
	procGetClient              = "registry.get_client"
	procListIntendedUses       = "registry.list_intended_uses"
	procGetIntendedUse         = "registry.get_intended_use"
	procGetWRPRCForIntendedUse = "registry.get_wrprc_for_intended_use"
	procCreateTemplate         = "registry.create_template"
	procGetTemplate            = "registry.get_template"
	procListTemplates          = "registry.list_templates"
	procDeleteTemplate         = "registry.delete_template"
	procCreateAPIKey           = "registry.create_api_key"
	procRevokeAPIKey           = "registry.revoke_api_key"
	procCreateClient           = "registry.create_client"
	procSetIntendedUses        = "registry.set_intended_uses"
)

// Client is a registry.client row as projected by registry.get_client. Legal
// entity / config data only — never attribute values.
type Client struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Status           string          `json:"status"` // active|suspended|offboarded
	RegistryURI      string          `json:"registry_uri"`
	ClientIdentifier string          `json:"client_identifier"` // registrar `sub`
	DefaultWebhook   string          `json:"default_webhook_url"`
	AllowedOrigins   []string        `json:"allowed_origins"`
	Policy           json.RawMessage `json:"policy"` // client policy JSON (eudi-verifier-core shape)
}

// IntendedUse is a registry.intended_use row.
type IntendedUse struct {
	ID            string                     `json:"id"`
	IntendedUseID string                     `json:"intended_use_id"` // registrar-assigned (ARF TS5)
	Purpose       json.RawMessage            `json:"purpose"`
	Credentials   []RegisteredCredentialJSON `json:"credentials"`
	RevokedAt     string                     `json:"revoked_at,omitempty"` // YYYY-MM-DD, empty = active
}

// RegisteredCredentialJSON is the canonical registry projection consumed by
// dcql.WithinScope — field-for-field dcql.RegisteredCredential with JSON
// tags. Each dcql.ClaimPath marshals to a JSON array of string|int|null (a
// []any), so Claims here is [][]any, a slice of that JSON array form. The
// onboarding wizard writes this shape.
type RegisteredCredentialJSON struct {
	Format         string   `json:"format"`
	DoctypesOrVCTs []string `json:"doctypes_or_vcts"`
	AllClaims      bool     `json:"all_claims"`
	Claims         [][]any  `json:"claims,omitempty"` // dcql.ClaimPath JSON form
}

// Template is a registry.template row.
type Template struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description,omitempty"`
	IntendedUseID string          `json:"intended_use_id"`
	DCQLQuery     json.RawMessage `json:"dcql_query"`
	CreatedAt     time.Time       `json:"created_at"`
}

// APIKeyRecord is the row registry.get_client_by_key_prefix projects — the
// seam the auth middleware verifies the presented secret against.
type APIKeyRecord struct {
	KeyID      string `json:"key_id"`
	ClientID   string `json:"client_id"`
	SecretHash string `json:"secret_hash"` // argon2id PHC string
	Status     string `json:"client_status"`
	Revoked    bool   `json:"revoked"`
}

// Store is the seam unit tests fake (fake.go) and production backs with PG
// (below). Every method that takes a clientID enforces isolation on the
// procedure side — cross-client access returns registry:not_found (404),
// never a distinguishable 403 (no existence leak).
type Store interface {
	GetClientByKeyPrefix(ctx context.Context, prefix string) (*APIKeyRecord, error)
	GetClient(ctx context.Context, clientID string) (*Client, error)
	ListIntendedUses(ctx context.Context, clientID string) ([]IntendedUse, error)
	GetIntendedUse(ctx context.Context, clientID, intendedUseID string) (*IntendedUse, error)
	GetWRPRCForIntendedUse(ctx context.Context, clientID, intendedUseID string) ([]byte, error) // nil when absent (graceful fallback)
	CreateTemplate(ctx context.Context, clientID string, t *Template) (string, error)
	GetTemplate(ctx context.Context, clientID, templateID string) (*Template, error)
	ListTemplates(ctx context.Context, clientID string) ([]Template, error)
	DeleteTemplate(ctx context.Context, clientID, templateID string) error
	CreateAPIKey(ctx context.Context, clientID, prefix, secretHash string) (string, error)
	RevokeAPIKey(ctx context.Context, clientID, keyID string) error
	CreateClient(ctx context.Context, c *Client) (string, error)                   // seed/test/onboarding
	SetIntendedUses(ctx context.Context, clientID string, ius []IntendedUse) error // seed/test/onboarding
}

// PG is the production Store: it calls the registry-schema procedures
// through the pgx pool (never raw table SQL).
type PG struct{ pool *pgxpool.Pool }

// NewPG returns a PG-backed Store over pool.
func NewPG(pool *pgxpool.Pool) *PG { return &PG{pool: pool} }

// GetClientByKeyPrefix resolves an API key prefix to its owning client and
// secret hash via registry.get_client_by_key_prefix (err:registry:not_found
// → 404 for an unknown prefix).
func (p *PG) GetClientByKeyPrefix(ctx context.Context, prefix string) (*APIKeyRecord, error) {
	data, err := call(ctx, p.pool, procGetClientByKeyPrefix, map[string]string{"prefix": prefix})
	if err != nil {
		return nil, err
	}
	var rec APIKeyRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// GetClient returns the client row via registry.get_client.
func (p *PG) GetClient(ctx context.Context, clientID string) (*Client, error) {
	data, err := call(ctx, p.pool, procGetClient, map[string]string{"client_id": clientID})
	if err != nil {
		return nil, err
	}
	var c Client
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ListIntendedUses returns every intended use registered for clientID via
// registry.list_intended_uses. An unknown/empty client yields an empty slice,
// not an error — this is a list read, not a single-resource lookup.
func (p *PG) ListIntendedUses(ctx context.Context, clientID string) ([]IntendedUse, error) {
	data, err := call(ctx, p.pool, procListIntendedUses, map[string]string{"client_id": clientID})
	if err != nil {
		return nil, err
	}
	var out struct {
		IntendedUses []IntendedUse `json:"intended_uses"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.IntendedUses, nil
}

// GetIntendedUse returns one intended use scoped to clientID via
// registry.get_intended_use (err:registry:not_found → 404 when absent or
// owned by another client).
func (p *PG) GetIntendedUse(ctx context.Context, clientID, intendedUseID string) (*IntendedUse, error) {
	data, err := call(ctx, p.pool, procGetIntendedUse,
		map[string]string{"client_id": clientID, "intended_use_id": intendedUseID})
	if err != nil {
		return nil, err
	}
	var iu IntendedUse
	if err := json.Unmarshal(data, &iu); err != nil {
		return nil, err
	}
	return &iu, nil
}

// GetWRPRCForIntendedUse returns the newest non-replaced, non-expired WRPRC
// bytes for (clientID, intendedUseID), or nil when none exists. A WRPRC is
// optional per Member State, so absence is the graceful registrar-reference
// fallback — never an error (the procedure always returns success; this
// method decodes the base64 "raw" field when present).
func (p *PG) GetWRPRCForIntendedUse(ctx context.Context, clientID, intendedUseID string) ([]byte, error) {
	data, err := call(ctx, p.pool, procGetWRPRCForIntendedUse,
		map[string]string{"client_id": clientID, "intended_use_id": intendedUseID})
	if err != nil {
		return nil, err
	}
	var out struct {
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if out.Raw == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(out.Raw)
	if err != nil {
		return nil, fmt.Errorf("registrydb: decode wrprc raw: %w", err)
	}
	return raw, nil
}

// CreateTemplate validates (inside the procedure) that intendedUseID exists
// for clientID and is not revoked, then inserts it via
// registry.create_template. On success t.ID/t.CreatedAt are filled in.
func (p *PG) CreateTemplate(ctx context.Context, clientID string, t *Template) (string, error) {
	in := map[string]any{
		"client_id":       clientID,
		"name":            t.Name,
		"description":     t.Description,
		"intended_use_id": t.IntendedUseID,
		"dcql_query":      t.DCQLQuery,
	}
	data, err := call(ctx, p.pool, procCreateTemplate, in)
	if err != nil {
		return "", err
	}
	var out struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	t.ID = out.ID
	t.CreatedAt = out.CreatedAt
	return out.ID, nil
}

// GetTemplate returns one template scoped to clientID via
// registry.get_template (err:registry:not_found → 404 for another client's
// or a soft-deleted template — same code either way, no existence leak).
func (p *PG) GetTemplate(ctx context.Context, clientID, templateID string) (*Template, error) {
	data, err := call(ctx, p.pool, procGetTemplate,
		map[string]string{"client_id": clientID, "template_id": templateID})
	if err != nil {
		return nil, err
	}
	var t Template
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTemplates returns every non-deleted template owned by clientID.
func (p *PG) ListTemplates(ctx context.Context, clientID string) ([]Template, error) {
	data, err := call(ctx, p.pool, procListTemplates, map[string]string{"client_id": clientID})
	if err != nil {
		return nil, err
	}
	var out struct {
		Templates []Template `json:"templates"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Templates, nil
}

// DeleteTemplate soft-deletes a template owned by clientID via
// registry.delete_template (err:registry:not_found → 404 for another
// client's or an already-deleted template).
func (p *PG) DeleteTemplate(ctx context.Context, clientID, templateID string) error {
	_, err := call(ctx, p.pool, procDeleteTemplate,
		map[string]string{"client_id": clientID, "template_id": templateID})
	return err
}

// CreateAPIKey mints a new key row via registry.create_api_key. Secret
// hashing happens in Go (argon2id) — this method only ever passes the
// resulting PHC string through.
func (p *PG) CreateAPIKey(ctx context.Context, clientID, prefix, secretHash string) (string, error) {
	data, err := call(ctx, p.pool, procCreateAPIKey,
		map[string]string{"client_id": clientID, "prefix": prefix, "secret_hash": secretHash})
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// RevokeAPIKey revokes a key owned by clientID via registry.revoke_api_key
// (err:registry:not_found → 404 when keyID belongs to another client).
func (p *PG) RevokeAPIKey(ctx context.Context, clientID, keyID string) error {
	_, err := call(ctx, p.pool, procRevokeAPIKey, map[string]string{"client_id": clientID, "key_id": keyID})
	return err
}

// CreateClient inserts a new client row via registry.create_client (a
// seed/test/onboarding primitive). On success c.ID is filled in.
func (p *PG) CreateClient(ctx context.Context, c *Client) (string, error) {
	origins := c.AllowedOrigins
	if origins == nil {
		origins = []string{} // avoid marshaling a bare JSON null into the jsonb column
	}
	policy := c.Policy
	if len(policy) == 0 {
		policy = json.RawMessage(`{}`)
	}
	in := map[string]any{
		"name":                c.Name,
		"registry_uri":        c.RegistryURI,
		"client_identifier":   c.ClientIdentifier,
		"default_webhook_url": c.DefaultWebhook,
		"allowed_origins":     origins,
		"policy":              policy,
	}
	data, err := call(ctx, p.pool, procCreateClient, in)
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	c.ID = out.ID
	return out.ID, nil
}

// SetIntendedUses replaces the full set of intended uses for clientID via
// registry.set_intended_uses (a seed/test/onboarding primitive). A nil/empty
// ius clears every intended use the client had.
func (p *PG) SetIntendedUses(ctx context.Context, clientID string, ius []IntendedUse) error {
	if ius == nil {
		ius = []IntendedUse{} // avoid marshaling a bare JSON null (jsonb_array_elements would error)
	}
	_, err := call(ctx, p.pool, procSetIntendedUses,
		map[string]any{"client_id": clientID, "intended_uses": ius})
	return err
}
