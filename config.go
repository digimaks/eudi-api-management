package eudiapimanagement

import (
	"time"

	pkconfig "github.com/gmb-lib/go-platform-kit/config"

	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration embeds the kit base config (SERVICE_NAME, ENVIRONMENT, LOG_*,
// METRICS_ENABLED, OTEL_*, RATELIMIT_* …) and adds this service's own fields.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// PostgresDSN connects as the EXECUTE-only management_public role.
	// Secret (carries the DB password): supports the POSTGRES_DSN_FILE form.
	PostgresDSN string `mapstructure:"postgres_dsn" validate:"required"`
	// ValkeyURL is the shared Valkey (handoff queue, respcode, retry state) as
	// a redis:// or rediss:// URL (user, database index and TLS options ride
	// in the URL).
	ValkeyURL string `mapstructure:"valkey_url" validate:"required"`
	// ValkeyPassword, when set, overrides the password in ValkeyURL. Also
	// readable through the VALKEY_PASSWORD_FILE indirection so a platform can
	// mount it. Secret — must never appear in logs, events, or error messages.
	ValkeyPassword string `mapstructure:"valkey_password"`
	// ValkeyKeyPrefix is prepended (as "<prefix>:") to every Valkey key. Set it
	// when the instance confines this user to a key pattern; every service
	// sharing the cache must carry the same value. Empty = no prefix.
	ValkeyKeyPrefix string `mapstructure:"valkey_key_prefix"`

	// VerifierInternalURL is eudi-verifier-core's base URL for the internal session
	// API. Cluster-internal; never exposed publicly.
	VerifierInternalURL string `mapstructure:"verifier_internal_url" validate:"required,url"`
	// InternalAPIToken authenticates this service to eudi-verifier-core's /internal
	// routes (constant-time compared there). Secret: prefer the _FILE form.
	InternalAPIToken string `mapstructure:"internal_api_token" validate:"required"`

	// Same operator key files eudi-verifier-core mounts.
	HandoffEncKeyFile     string `mapstructure:"handoff_enc_key_file" validate:"required"`
	WebhookSigningKeyFile string `mapstructure:"webhook_signing_key_file" validate:"required"`

	// SessionDefaultTTL mirrors the API contract (ttlSeconds 60..3600, default 300).
	SessionDefaultTTL time.Duration `mapstructure:"session_default_ttl" validate:"required,gt=0"`

	// Webhook delivery. RetryBaseDelay doubles per attempt, capped by the
	// envelope's expires_at: retries live inside the result TTL.
	WebhookTimeout    time.Duration `mapstructure:"webhook_timeout" validate:"required,gt=0"`
	RetryBaseDelay    time.Duration `mapstructure:"webhook_retry_base_delay" validate:"required,gt=0"`
	RetryMaxAttempts  int           `mapstructure:"webhook_retry_max_attempts" validate:"required,gt=0"`
	ConsumerPollEvery time.Duration `mapstructure:"handoff_poll_interval" validate:"required,gt=0"`

	// Rate limits for session creation, per API key and per client IP.
	SessionRateLimitPerKey int           `mapstructure:"session_rate_limit_per_key" validate:"required,gt=0"`
	SessionRateLimitPerIP  int           `mapstructure:"session_rate_limit_per_ip" validate:"required,gt=0"`
	SessionRateWindow      time.Duration `mapstructure:"session_rate_window" validate:"required,gt=0"`
}

// NewConfiguration returns a Configuration with the embedded kit base
// configuration initialized.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// Bind registers defaults and environment-variable bindings with viper; it
// must call the embedded BaseConfiguration.Bind first.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)

	v.SetDefault("session_default_ttl", 5*time.Minute)
	v.SetDefault("webhook_timeout", 10*time.Second)
	v.SetDefault("webhook_retry_base_delay", 30*time.Second)
	v.SetDefault("webhook_retry_max_attempts", 8)
	v.SetDefault("handoff_poll_interval", time.Second)
	v.SetDefault("session_rate_limit_per_key", 50)
	v.SetDefault("session_rate_limit_per_ip", 100)
	v.SetDefault("session_rate_window", time.Minute)

	// Secrets: prefer the Vault-agent <NAME>_FILE convention (loadSecret sets a
	// viper default from the file's content); an explicit plain env var still
	// overrides it. POSTGRES_DSN carries the DB password; INTERNAL_API_TOKEN is
	// the shared cluster-internal secret (the field doc's "prefer the _FILE
	// form"). The *_KEY_FILE vars are PEM PATHS, not this convention.
	loadSecret(v, "postgres_dsn", "POSTGRES_DSN")
	loadSecret(v, "internal_api_token", "INTERNAL_API_TOKEN")
	loadSecret(v, "valkey_password", "VALKEY_PASSWORD")

	_ = v.BindEnv("postgres_dsn", "POSTGRES_DSN")
	_ = v.BindEnv("valkey_url", "VALKEY_URL")
	_ = v.BindEnv("valkey_password", "VALKEY_PASSWORD")
	_ = v.BindEnv("valkey_key_prefix", "VALKEY_KEY_PREFIX")
	_ = v.BindEnv("verifier_internal_url", "VERIFIER_INTERNAL_URL")
	_ = v.BindEnv("internal_api_token", "INTERNAL_API_TOKEN")
	_ = v.BindEnv("handoff_enc_key_file", "HANDOFF_ENC_KEY_FILE")
	_ = v.BindEnv("webhook_signing_key_file", "WEBHOOK_SIGNING_KEY_FILE")
	_ = v.BindEnv("session_default_ttl", "SESSION_DEFAULT_TTL")
	_ = v.BindEnv("webhook_timeout", "WEBHOOK_TIMEOUT")
	_ = v.BindEnv("webhook_retry_base_delay", "WEBHOOK_RETRY_BASE_DELAY")
	_ = v.BindEnv("webhook_retry_max_attempts", "WEBHOOK_RETRY_MAX_ATTEMPTS")
	_ = v.BindEnv("handoff_poll_interval", "HANDOFF_POLL_INTERVAL")
	_ = v.BindEnv("session_rate_limit_per_key", "SESSION_RATE_LIMIT_PER_KEY")
	_ = v.BindEnv("session_rate_limit_per_ip", "SESSION_RATE_LIMIT_PER_IP")
	_ = v.BindEnv("session_rate_window", "SESSION_RATE_WINDOW")
}

// Validate validates the embedded base configuration, then this service's own
// fields.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	return valid.Struct(c)
}

// loadSecret resolves a secret from the secret store (Vault agent ->
// <NAME>_FILE) and registers it as a viper default, so an explicit plain env
// var still overrides it.
func loadSecret(v *viper.Viper, key, name string) {
	if secret, err := corecfg.LoadRemoteSecret(name); err == nil && secret != "" {
		v.SetDefault(key, secret)
	}
}
