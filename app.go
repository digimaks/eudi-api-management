// Package eudiapimanagement is the client-facing management API of the EUDI
// verifier. It is a public boundary, so error responses expose problem details
// (PublicErrors=true).
package eudiapimanagement

import (
	"context"
	"net/http"
	"time"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	"github.com/gmb-eudi/go-eudi-crypto/filekeys"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-platform-kit/observability"
	"github.com/gmb-lib/go-platform-kit/platform"

	"github.com/digimaks/eudi-api-management/internal/keyspace"
	"github.com/digimaks/eudi-api-management/internal/registrydb"
	"github.com/digimaks/eudi-api-management/internal/sessiondb"
	"github.com/digimaks/eudi-api-management/internal/vcclient"
	"github.com/digimaks/eudi-api-management/internal/webhook"
)

// sweeperInterval is the expiry-sweeper tick. Fixed at 30s rather than
// configurable.
const sweeperInterval = 30 * time.Second

// sweeperBatchLimit bounds one sweep's batch of due sessions to expire —
// generous enough that a healthy deployment always drains its due backlog in
// one tick at sweeperInterval.
const sweeperBatchLimit = 200

// Key ids in the shared operator KeyProvider namespace. These MUST match the
// key ids used by eudi-verifier-core — the JWKS kid is part of the wire contract.
const (
	KeyHandoffEnc     = "handoff-enc"     // decrypt handoff result_jwe
	KeyWebhookSigning = "webhook-signing" // detached JWS on webhook POSTs
)

// App is the eudi-api-management application container: it embeds *azugo.App and
// holds every service-level dependency (config, cache, DB, keys).
type App struct {
	*azugo.App

	config   *Configuration
	db       *pgxpool.Pool
	valkey   redis.UniversalClient
	prefix   keyspace.Prefix // deployment key prefix for every Valkey key (shared with the producer)
	keys     crypto.KeyProvider
	registry registrydb.Store
	sessions sessiondb.Store
	vc       *vcclient.Client

	// testRedis is the in-process miniredis handle backing TestApp's Valkey
	// client (set by TestApp; nil in production). It lets tests inspect every
	// Valkey key/value directly (e.g. purge canaries). Typed as `any` (not
	// *miniredis.Miniredis) so this production file carries no import of the
	// test-only miniredis/gopher-lua dependency tree: the test helpers are
	// gated behind a build tag so the production binary's dependency closure
	// excludes them, and a concretely-typed field here would have defeated
	// that. TestMiniredis() type-asserts back to *miniredis.Miniredis.
	testRedis any
}

// New builds the eudi-api-management App: server.New wires Azugo, then init layers
// platform.Setup and the service's own dependencies on top.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	// Session creation gets two hand-wired rate limiters (per client id and
	// per client IP) instead of azugo's global auto-limiter, which would
	// otherwise apply the SAME limit to every route (health checks, polling
	// GET /sessions/{id}, templates). Disable the automatic global middleware
	// here; the manual limiters are applied to POST /sessions alone.
	a, err := server.New(cmd, server.Options{
		AppName:       "Management API",
		AppVer:        version,
		Configuration: config,
	}, server.DisableAutoRateLimit())
	if err != nil {
		return nil, err
	}

	app := &App{App: a, config: config}
	if err := app.init(); err != nil {
		return nil, err
	}
	return app, nil
}

func (a *App) init() error {
	// Error taxonomy — every problem code this service produces is registered
	// here, before Setup, in a single place. Statuses outside the kit's
	// built-in reason map need explicit specs.
	pkerrors.RegisterReason("notRegistered", pkerrors.ReasonSpec{Status: 403, Title: "Client not registered"})
	pkerrors.RegisterReason("scopeExceeded", pkerrors.ReasonSpec{Status: 403, Title: "Requested attributes exceed registered intended use"})
	pkerrors.RegisterReason("originNotRegistered", pkerrors.ReasonSpec{Status: 403, Title: "URI origin not pre-registered for client"})
	pkerrors.RegisterReason("intendedUseRevoked", pkerrors.ReasonSpec{Status: 422, Title: "Intended use revoked"})
	// err:client:registrarIdentityRequired — the client's stored registration
	// has no usable registrar identity (registrar URL + assigned identifier),
	// so the registration reference every wallet request must carry cannot be
	// built. A client-configuration gap, like intendedUseRequired: the
	// registration API records the identity, this service can only report it.
	pkerrors.RegisterReason("registrarIdentityRequired", pkerrors.ReasonSpec{Status: 422, Title: "Client registrar identity required"})
	// NOTE: no reason named "unavailable" is registered here on purpose. A
	// reason registration applies to EVERY code with that reason segment, and
	// this service mints err:upstream:unavailable for a verifier engine that did
	// not answer — a registration titled for the registrar would re-title those.
	// The upstream problems carry their own title (internal/vcclient).
	pkerrors.RegisterReason("deliveryFailed", pkerrors.ReasonSpec{Status: 502, Title: "Webhook delivery failed"})
	pkerrors.RegisterReason("notCancellable", pkerrors.ReasonSpec{Status: 409, Title: "Session not cancellable"})
	pkerrors.RegisterReason("intendedUseRequired", pkerrors.ReasonSpec{Status: 422, Title: "Intended use required"})
	// err:session:not_found — the session.* stored procedures raise their own
	// not_found reason, so this makes the wire code domain-specific
	// (err:session:not_found) instead of the kit's generic built-in "Not found"
	// bucket (which would otherwise render as err:request:notFound, hiding
	// which domain the id belongs to). AllowBuiltinOverride is required because
	// "not-found" normalizes to the same key as the built-in bucket this
	// registration shadows. Distinct from err:template:notFound, which is
	// authored directly in Go via NewProblem, never through this DB-envelope
	// path.
	pkerrors.RegisterReason("notFound", pkerrors.ReasonSpec{Status: 404, Title: "Not found"}, pkerrors.AllowBuiltinOverride())

	// Public boundary: PublicErrors=true plus the attribute-value redaction
	// extension.
	if err := platform.Setup(a.App, platform.Options{
		Config:       a.config.BaseConfiguration,
		Redaction:    RedactionPolicy(),
		PublicErrors: true,
	}); err != nil {
		return err
	}

	keys, err := filekeys.New(map[string]string{
		KeyHandoffEnc:     a.config.HandoffEncKeyFile,
		KeyWebhookSigning: a.config.WebhookSigningKeyFile,
	})
	if err != nil {
		return err
	}
	a.keys = keys

	a.db, err = pgxpool.New(context.Background(), a.config.PostgresDSN)
	if err != nil {
		return err
	}
	a.registry = registrydb.NewPG(a.db) // TestApp overrides with registrydb.NewFake()
	a.sessions = sessiondb.NewPG(a.db)  // TestApp overrides with sessiondb.NewFake()

	// vcclient is the ONLY way this service mints or kills an OID4VP session:
	// it calls eudi-verifier-core's internal API, because the database role this
	// service uses has no create_session grant. TestApp overrides it with a
	// client pointed at an httptest stub.
	a.vc = vcclient.New(a.config.VerifierInternalURL, a.config.InternalAPIToken)

	opts, err := redis.ParseURL(a.config.ValkeyURL)
	if err != nil {
		return err
	}
	if a.config.ValkeyPassword != "" {
		opts.Password = a.config.ValkeyPassword // a mounted secret wins over one embedded in the URL
	}
	a.valkey = redis.NewClient(opts)
	a.prefix = keyspace.New(a.config.ValkeyKeyPrefix)

	// Webhook delivery: a background queue consumer draining vc:handoff:queue
	// plus an expiry sweeper — both core.Tasker, wired via a.AddTask. Delivery
	// POSTs run with no *azugo.Context (there is no inbound request to route
	// through httpclient.Outbound), so the doer is a plain
	// observability-instrumented *http.Client — no auth layer is needed for
	// this same-origin client-webhook POST.
	doer := observability.InstrumentHTTPClient(&http.Client{Timeout: a.config.WebhookTimeout})
	deliverer := webhook.NewDeliverer(doer, a.keys, a.config.WebhookTimeout)
	retrier := webhook.NewRetrier(a.valkey, a.config.RetryBaseDelay, a.config.RetryMaxAttempts, time.Now).WithKeyPrefix(a.prefix)
	if err := a.AddTask(webhook.NewConsumer(a.Log().Named("webhook-consumer"), a.valkey, a.prefix, a.sessions, deliverer, retrier, a.config.ConsumerPollEvery, time.Now)); err != nil {
		return err
	}
	if err := a.AddTask(webhook.NewSweeper(a.Log().Named("webhook-sweeper"), a.sessions, deliverer, sweeperBatchLimit, sweeperInterval)); err != nil {
		return err
	}

	return nil
}

// Config returns the loaded service configuration. It panics if the config is
// not loaded — a handler calling this before New() completes is a bug.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}
	return a.config
}

// DB returns the Postgres connection pool (the EXECUTE-only management_public
// role).
func (a *App) DB() *pgxpool.Pool { return a.db }

// Valkey returns the shared Valkey/Redis client (handoff queue, respcode,
// retry state).
func (a *App) Valkey() redis.UniversalClient { return a.valkey }

// KeyPrefix returns the deployment key prefix every Valkey key is stored
// under (empty when none is configured).
func (a *App) KeyPrefix() keyspace.Prefix { return a.prefix }

// Keys returns the operator key provider (handoff decryption, webhook
// signing — see the Key* constants above).
func (a *App) Keys() crypto.KeyProvider { return a.keys }

// Registry returns the registry-schema store (clients, intended uses,
// templates, API keys). init installs the pg-backed store; SetRegistry
// (a test-only seam) swaps in registrydb.NewFake().
func (a *App) Registry() registrydb.Store { return a.registry }

// SetRegistry swaps the registry store. Test-only seam: TestApp installs
// registrydb.NewFake() so unit tests never dial Postgres.
func (a *App) SetRegistry(s registrydb.Store) { a.registry = s }

// Sessions returns the session-schema store (poll/cancel). init installs the
// pg-backed store; SetSessions (a test-only seam) swaps in sessiondb.NewFake()
// — same pattern as Registry/SetRegistry above.
func (a *App) Sessions() sessiondb.Store { return a.sessions }

// SetSessions swaps the session store. Test-only seam: TestApp installs
// sessiondb.NewFake() so unit tests never dial Postgres.
func (a *App) SetSessions(s sessiondb.Store) { a.sessions = s }

// VC returns the eudi-verifier-core internal-API client (session create/delete
// transport).
func (a *App) VC() *vcclient.Client { return a.vc }

// SetVC swaps the eudi-verifier-core client. Test-only seam: unit tests point it
// at an httptest.Server stub instead of a real eudi-verifier-core deployment.
func (a *App) SetVC(c *vcclient.Client) { a.vc = c }
