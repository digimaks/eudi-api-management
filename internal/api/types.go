// Package api holds the wire DTOs of this service's HTTP API. They are
// hand-written rather than generated: the contract is OpenAPI 3.1, and
// oapi-codegen is 3.0-only and produces lossy output on this document.
package api

import (
	"errors"
	"time"
)

// SessionRequest is the body of POST /sessions.
type SessionRequest struct {
	Presentation    Presentation     `json:"presentation"`
	Flow            string           `json:"flow,omitempty"` // same_device|cross_device|dc_api (default cross_device)
	IntendedUseID   string           `json:"intendedUseId,omitempty"`
	RedirectURI     string           `json:"redirectUri,omitempty"`
	WebhookURL      string           `json:"webhookUrl,omitempty"`
	TTLSeconds      int              `json:"ttlSeconds,omitempty"` // 60..3600, default 300
	TransactionData []map[string]any `json:"transactionData,omitempty"`
}

// Presentation is SessionRequest's inline `presentation` object (not a named
// component schema in the YAML — exactly one of TemplateID or DCQLQuery).
type Presentation struct {
	TemplateID string         `json:"templateId,omitempty"`
	DCQLQuery  map[string]any `json:"dcqlQuery,omitempty"` // exactly one of the two
}

// SessionCreated is the 201 response of POST /sessions.
type SessionCreated struct {
	SessionID    string         `json:"sessionId"`
	State        string         `json:"state"` // always "pending"
	WalletURL    string         `json:"walletUrl"`
	QRPayload    string         `json:"qrPayload,omitempty"`
	DCAPIRequest map[string]any `json:"dcApiRequest,omitempty"`
	// DCAPIResponseURI is where the CALLING PAGE posts the credential data the
	// browser returned from navigator.credentials.get(). Set for the dc_api
	// flow only: there the response travels back through the browser, so the
	// endpoint cannot be carried inside the request object and the caller has
	// no other way to learn it. The other flows deliberately omit it — their
	// endpoint is addressed by the wallet, not by the caller, and naming it
	// here would invite a caller to post to it.
	//
	// The value is the opaque token-routed URL minted by the verifier engine;
	// it is never derived from sessionId and never exposes the engine's own
	// session identifier.
	DCAPIResponseURI string    `json:"dcApiResponseUri,omitempty"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

// Session is the 200 response of GET /sessions/{sessionId}.
type Session struct {
	SessionID   string              `json:"sessionId"`
	State       string              `json:"state"` // pending|wallet_engaged|verified|failed|expired|cancelled
	CreatedAt   time.Time           `json:"createdAt"`
	CompletedAt *time.Time          `json:"completedAt,omitempty"`
	Report      *VerificationReport `json:"report,omitempty"`
	Result      *VerificationResult `json:"result,omitempty"`
	Failure     *Failure            `json:"failure,omitempty"`
}

// Failure is the inline `failure` object shared by Session and WebhookPayload
// in the YAML. NOTE: Session.failure declares {code, detail} while
// WebhookPayload.failure declares {code} only — the YAML does not $ref
// a shared "Failure" schema for either. This DTO uses one superset struct for
// both call sites (Detail always omitempty); WebhookPayload never populates
// Detail, so the wire shape stays byte-for-byte within that schema's declared
// properties. Not a named component in the YAML.
type Failure struct {
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// VerificationReport is a shared component ($ref'd by Session and
// WebhookPayload).
// Contains claim NAMES only, never values (ARF AS-RP-01-002).
type VerificationReport struct {
	Checks []ReportCheck `json:"checks,omitempty"`
}

// ReportCheck is VerificationReport's inline `checks[]` item (not a named
// component schema in the YAML).
type ReportCheck struct {
	Check         string `json:"check"` // response_integrity|parse|issuer_authenticity|data_integrity|revocation|device_binding|user_binding|query_fulfilment
	CredentialRef string `json:"credentialRef,omitempty"`
	Outcome       string `json:"outcome"` // pass|fail|skipped_by_policy
	Code          string `json:"code,omitempty"`
	SpecRef       string `json:"specRef,omitempty"` // e.g. [ARF §6.6.3.7]
}

// VerificationResult is a shared component ($ref'd by Session and
// WebhookPayload).
// Delivered via webhook and available via polling only within the result TTL;
// deleted afterwards (ARF AS-RP-51-011).
type VerificationResult struct {
	Credentials []ResultCredential `json:"credentials,omitempty"`
}

// ResultCredential is VerificationResult's inline `credentials[]` item (not a
// named component schema in the YAML).
type ResultCredential struct {
	QueryID       string         `json:"queryId"`
	Format        string         `json:"format"` // mso_mdoc | dc+sd-jwt
	DoctypeOrVCT  string         `json:"doctypeOrVct,omitempty"`
	IssuerCountry string         `json:"issuerCountry,omitempty"`
	Claims        map[string]any `json:"claims"`
}

// TemplateNew is the body of POST /templates.
type TemplateNew struct {
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	IntendedUseID string         `json:"intendedUseId"`
	DCQLQuery     map[string]any `json:"dcqlQuery"`
}

// Template is the response shape of the template endpoints: TemplateNew plus
// {templateId, createdAt}, mirrored here as an embedded TemplateNew field.
type Template struct {
	TemplateNew
	TemplateID string    `json:"templateId"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Problem is the RFC 9457 problem+json body returned for every error
// response, on every operation. Code is the stable machine
// identifier (err:domain:reason).
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	Code     string `json:"code"`
}

// WebhookPayload is POSTed to the client's webhook on terminal session
// states.
// The body is covered by a detached JWS in the X-Payload-Signature header
// (operator key; JWKS at /.well-known/verifier-jwks.json).
type WebhookPayload struct {
	SessionID string              `json:"sessionId"`
	State     string              `json:"state"` // verified|failed|expired
	Report    *VerificationReport `json:"report,omitempty"`
	Result    *VerificationResult `json:"result,omitempty"`
	Failure   *Failure            `json:"failure,omitempty"`
}

// ErrUnknownFlow is returned by FlowToDB for any flow value outside the
// SessionRequest.flow enum.
var ErrUnknownFlow = errors.New("api: unknown flow")

// FlowToDB maps the API flow enum onto the DB/internal enum
// (`dc_api` ⇔ the session schema's CHECK constraint `dcapi`).
func FlowToDB(apiFlow string) (string, error) {
	switch apiFlow {
	case "", "cross_device":
		return "cross_device", nil
	case "same_device":
		return "same_device", nil
	case "dc_api":
		return "dcapi", nil
	}
	return "", ErrUnknownFlow
}

// FlowFromDB maps the DB/internal flow enum back onto the API's
// (`dcapi` ⇔ `dc_api`); every other value passes through unchanged.
func FlowFromDB(dbFlow string) string {
	if dbFlow == "dcapi" {
		return "dc_api"
	}
	return dbFlow
}
