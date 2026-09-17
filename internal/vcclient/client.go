// Package vcclient is eudi-api-management's client for eudi-verifier-core's
// cluster-internal session API. It is the ONLY way this service mints or
// kills an OID4VP session: management_public has no create_session grant, so
// eudi-verifier-core's internal API is the sole writer of the session row.
package vcclient

import (
	"encoding/json"
	"fmt"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-lib/go-platform-kit/correlation"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-platform-kit/httpclient"
)

// sessionsPath is eudi-verifier-core's internal session-creation path
// (/internal/v1/sessions).
const sessionsPath = "/internal/v1/sessions"

// sourceService is the id this service stamps on the problems it originates
// for a failed engine call.
const sourceService = "eudi-api-management"

// Unavailable is the problem this service returns when eudi-verifier-core did
// not answer usably — unreachable, timed out, or an answer that cannot be
// decoded. One constructor for every such path, so they agree on code, status
// and title; only the detail differs, and it stays internal (it reaches the
// log, never the caller) because it describes this deployment's topology, not
// the caller's request. The title names the engine explicitly rather than
// relying on the taxonomy: the code's reason segment is shared with other
// "unavailable" codes, and a title inherited from one of them would point an
// operator at the wrong system.
func Unavailable(what string, cause error) error {
	detail := what
	if cause != nil {
		detail += ": " + cause.Error()
	}
	return pkerrors.NewProblem("err:upstream:unavailable",
		pkerrors.WithStatus(fasthttp.StatusBadGateway),
		pkerrors.WithSource(sourceService),
		pkerrors.WithTitle("Verifier engine unavailable"),
		pkerrors.WithDetail(detail))
}

// CreateRequest is the wire body of eudi-verifier-core's POST /internal/v1/sessions
// — the field names ARE that endpoint's contract.
type CreateRequest struct {
	ClientID        string                 `json:"client_id"`
	CorrelationID   string                 `json:"correlation_id"`
	Flow            string                 `json:"flow"` // DB enum: same_device|cross_device|dcapi
	DCQLQuery       json.RawMessage        `json:"dcql_query"`
	Policy          json.RawMessage        `json:"policy,omitempty"`
	WebhookURL      string                 `json:"webhook_url"`
	RedirectURI     string                 `json:"redirect_uri,omitempty"`
	Registration    rpcert.RegistrationRef `json:"registration"` // marshals to {name,sub,registry_uri,intended_use_id}
	WRPRC           []byte                 `json:"wrprc,omitempty"`
	ExpectedOrigins []string               `json:"expected_origins,omitempty"`
	TTLSeconds      int                    `json:"ttl_seconds,omitempty"`
}

// CreateResponse is the 201 response body of the same endpoint.
type CreateResponse struct {
	SessionID   string    `json:"session_id"`
	ExpiresAt   time.Time `json:"expires_at"` // effective (server may clamp ttl_seconds)
	RequestURI  string    `json:"request_uri"`
	ResponseURI string    `json:"response_uri"`
	Invocation  struct {
		SchemeURI    string          `json:"scheme_uri,omitempty"`
		WalletURL    string          `json:"wallet_url"`
		QRPayload    string          `json:"qr_payload,omitempty"`
		DCAPIRequest json.RawMessage `json:"dc_api_request,omitempty"`
	} `json:"invocation"`
}

// Client talks to eudi-verifier-core's internal session API over the shared
// context-bound HTTP client (correlation + tracing; never a raw http.Client).
type Client struct {
	baseURL string
	token   string // sent as "Authorization: Bearer <token>"
}

// New returns a Client targeting baseURL, authenticating with token — which
// eudi-verifier-core compares against its configured bearer token in constant time
// (sha256, constant-time compare).
func New(baseURL, token string) *Client {
	return &Client{baseURL: baseURL, token: token}
}

// CreateSession calls POST /internal/v1/sessions. On a non-2xx response it
// relays the downstream problem intact — never collapsing it to a bare
// 502/500.
func (c *Client) CreateSession(ctx *azugo.Context, req *CreateRequest) (*CreateResponse, error) {
	var resp CreateResponse
	if err := c.do(ctx, fasthttp.MethodPost, sessionsPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteSession calls DELETE /internal/v1/sessions/{sessionID}. Idempotent:
// eudi-verifier-core's internal DELETE always returns 204, "nothing to delete"
// included.
func (c *Client) DeleteSession(ctx *azugo.Context, sessionID string) error {
	return c.do(ctx, fasthttp.MethodDelete, sessionsPath+"/"+sessionID, nil, nil)
}

// do issues one request against eudi-verifier-core's internal API using
// httpclient.Outbound (correlation + tracing). It deliberately uses the
// low-level Client.Do/NewRequest/NewResponse primitives rather than the
// high-level PostJSON/Delete helpers: those collapse any non-2xx response
// into a Go error that keeps at most the first 100 body bytes
// (azugo.io/core/http Response.Error) — which would make relaying the
// downstream RFC 9457 problem body impossible. Consequently it also can't
// spread httpclient.CorrelationOptions's RequestOption values into the call
// (Request.apply is unexported, reachable only from inside
// azugo.io/core/http's own high-level methods) — it replicates that helper's
// effect directly via correlation.ID, which is what CorrelationOptions calls
// internally.
func (c *Client) do(ctx *azugo.Context, method, path string, body, out any) error {
	hc := httpclient.Outbound(ctx, c.baseURL)

	req := hc.NewRequest()
	defer hc.ReleaseRequest(req)

	if err := req.SetRequestURL(path); err != nil {
		return err
	}
	req.Header.SetMethod(method)
	req.Header.Set(fasthttp.HeaderAuthorization, "Bearer "+c.token)
	if cid := correlation.ID(ctx); cid != "" {
		req.Header.Set(correlation.HeaderCorrelationID, cid)
	}

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		req.Header.SetContentType("application/json")
		req.SetBodyRaw(b)
	}

	resp := hc.NewResponse()
	defer hc.ReleaseResponse(resp)

	if err := hc.Do(req, resp); err != nil {
		// Transport failure (eudi-verifier-core unreachable/timed out): fail
		// closed as "engine unavailable", with the cause kept for the log.
		return Unavailable("eudi-verifier-core did not answer", err)
	}

	respBody, err := resp.BodyUncompressed()
	if err != nil {
		return Unavailable("eudi-verifier-core response body could not be read", err)
	}

	if resp.StatusCode()/100 == 2 {
		if out != nil && len(respBody) > 0 {
			// A 2xx whose body does not decode is held to the same standard
			// as a non-2xx without a problem body: the engine answered, but
			// not usably. Never a bare decode error — that would render as a
			// server fault of this service with no cause anywhere.
			if err := json.Unmarshal(respBody, out); err != nil {
				return Unavailable("undecodable 2xx response body from eudi-verifier-core", err)
			}
		}
		return nil
	}

	// Non-2xx: relay the downstream problem intact — preserve the terminal
	// code/source/trace id and the status IT chose ("never lose the
	// original"). A non-conforming body (no problem to decode) becomes a
	// uniform "engine unavailable", never a raw/opaque error.
	if down, ok := pkerrors.ParseProblem(respBody); ok {
		return pkerrors.Relay(down, sourceService, down.Status)
	}
	return Unavailable(fmt.Sprintf("eudi-verifier-core answered %d without a problem body", resp.StatusCode()), nil)
}
