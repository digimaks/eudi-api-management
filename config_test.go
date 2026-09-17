package eudiapimanagement

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"azugo.io/core/validation"
	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

// TestConfigurationBindDefaults asserts every v.SetDefault call in Bind lands
// on the expected viper key with the expected value.
func TestConfigurationBindDefaults(t *testing.T) {
	v := viper.New()
	cfg := NewConfiguration()
	cfg.Bind("", v)

	cases := []struct {
		key  string
		want any
	}{
		{"session_default_ttl", 5 * time.Minute},
		{"webhook_timeout", 10 * time.Second},
		{"webhook_retry_base_delay", 30 * time.Second},
		{"webhook_retry_max_attempts", 8},
		{"handoff_poll_interval", time.Second},
		{"session_rate_limit_per_key", 50},
		{"session_rate_limit_per_ip", 100},
		{"session_rate_window", time.Minute},
	}
	for _, c := range cases {
		switch want := c.want.(type) {
		case time.Duration:
			qt.Check(t, qt.Equals(v.GetDuration(c.key), want), qt.Commentf("key %q", c.key))
		case int:
			qt.Check(t, qt.Equals(v.GetInt(c.key), want), qt.Commentf("key %q", c.key))
		}
	}
}

// TestConfigurationBindEnvVars asserts every BindEnv call actually wires the
// documented env var name onto the viper key — a typo here is a silent
// deploy-time outage, not a compile error.
func TestConfigurationBindEnvVars(t *testing.T) {
	envs := map[string]string{
		"POSTGRES_DSN":               "postgres://management_public@db/verifier",
		"VALKEY_URL":                 "redis://valkey:6379",
		"VERIFIER_INTERNAL_URL":      "http://eudi-verifier-core-internal:8080",
		"INTERNAL_API_TOKEN":         "test-token",
		"HANDOFF_ENC_KEY_FILE":       "/keys/handoff.pem",
		"WEBHOOK_SIGNING_KEY_FILE":   "/keys/webhook.pem",
		"SESSION_DEFAULT_TTL":        "7m",
		"WEBHOOK_TIMEOUT":            "3s",
		"WEBHOOK_RETRY_BASE_DELAY":   "15s",
		"WEBHOOK_RETRY_MAX_ATTEMPTS": "4",
		"HANDOFF_POLL_INTERVAL":      "2s",
		"SESSION_RATE_LIMIT_PER_KEY": "9",
		"SESSION_RATE_LIMIT_PER_IP":  "18",
		"SESSION_RATE_WINDOW":        "30s",
	}
	for k, val := range envs {
		t.Setenv(k, val)
	}

	v := viper.New()
	cfg := NewConfiguration()
	cfg.Bind("", v)

	qt.Check(t, qt.Equals(v.GetString("postgres_dsn"), envs["POSTGRES_DSN"]))
	qt.Check(t, qt.Equals(v.GetString("valkey_url"), envs["VALKEY_URL"]))
	qt.Check(t, qt.Equals(v.GetString("verifier_internal_url"), envs["VERIFIER_INTERNAL_URL"]))
	qt.Check(t, qt.Equals(v.GetString("internal_api_token"), envs["INTERNAL_API_TOKEN"]))
	qt.Check(t, qt.Equals(v.GetString("handoff_enc_key_file"), envs["HANDOFF_ENC_KEY_FILE"]))
	qt.Check(t, qt.Equals(v.GetString("webhook_signing_key_file"), envs["WEBHOOK_SIGNING_KEY_FILE"]))
	qt.Check(t, qt.Equals(v.GetDuration("session_default_ttl"), 7*time.Minute))
	qt.Check(t, qt.Equals(v.GetDuration("webhook_timeout"), 3*time.Second))
	qt.Check(t, qt.Equals(v.GetDuration("webhook_retry_base_delay"), 15*time.Second))
	qt.Check(t, qt.Equals(v.GetInt("webhook_retry_max_attempts"), 4))
	qt.Check(t, qt.Equals(v.GetDuration("handoff_poll_interval"), 2*time.Second))
	qt.Check(t, qt.Equals(v.GetInt("session_rate_limit_per_key"), 9))
	qt.Check(t, qt.Equals(v.GetInt("session_rate_limit_per_ip"), 18))
	qt.Check(t, qt.Equals(v.GetDuration("session_rate_window"), 30*time.Second))
}

// TestConfigurationSecretFileConvention asserts the opaque secrets POSTGRES_DSN
// and INTERNAL_API_TOKEN honor the platform's Vault-agent <NAME>_FILE
// secret-file convention (loadSecret → LoadRemoteSecret) — the latter fulfilling
// InternalAPIToken's "prefer the _FILE form" doc comment. LoadRemoteSecret trims
// surrounding whitespace, so a trailing newline in the mounted file is dropped.
func TestConfigurationSecretFileConvention(t *testing.T) {
	dir := t.TempDir()
	dsnFile := filepath.Join(dir, "dsn")
	tokFile := filepath.Join(dir, "tok")
	qt.Assert(t, qt.IsNil(os.WriteFile(dsnFile, []byte("postgres://management_public:filepw@db/verifier\n"), 0o600)))
	qt.Assert(t, qt.IsNil(os.WriteFile(tokFile, []byte("  token-from-file\n"), 0o600)))

	t.Setenv("POSTGRES_DSN_FILE", dsnFile)
	t.Setenv("INTERNAL_API_TOKEN_FILE", tokFile)

	v := viper.New()
	NewConfiguration().Bind("", v)

	qt.Check(t, qt.Equals(v.GetString("postgres_dsn"), "postgres://management_public:filepw@db/verifier"))
	qt.Check(t, qt.Equals(v.GetString("internal_api_token"), "token-from-file"))
}

// TestConfigurationPlainEnvOverridesSecretFile asserts an explicit plain env var
// still wins over the _FILE default (loadSecret only registers a viper default).
func TestConfigurationPlainEnvOverridesSecretFile(t *testing.T) {
	dir := t.TempDir()
	dsnFile := filepath.Join(dir, "dsn")
	qt.Assert(t, qt.IsNil(os.WriteFile(dsnFile, []byte("postgres://from-file@db/verifier"), 0o600)))

	t.Setenv("POSTGRES_DSN_FILE", dsnFile)
	t.Setenv("POSTGRES_DSN", "postgres://from-env@db/verifier")

	v := viper.New()
	NewConfiguration().Bind("", v)

	qt.Check(t, qt.Equals(v.GetString("postgres_dsn"), "postgres://from-env@db/verifier"))
}

// TestConfigurationValidateMissingRequiredField asserts a freshly constructed
// Configuration (every field at its zero value) fails validation — the
// fail-closed startup contract: this service must refuse to boot rather than
// run with an empty Postgres DSN / Valkey URL / internal token.
func TestConfigurationValidateMissingRequiredField(t *testing.T) {
	cfg := NewConfiguration()
	err := cfg.Validate(validation.New())
	qt.Assert(t, qt.IsNotNil(err))
}

// TestConfigurationValidatePassesWhenComplete is the positive counterpart:
// every required field populated (mirroring TestApp's env set, but asserted
// directly against Validate rather than through a full app boot) passes.
func TestConfigurationValidatePassesWhenComplete(t *testing.T) {
	cfg := NewConfiguration()
	cfg.ServiceName = "eudi-api-management"
	cfg.PostgresDSN = "postgres://management_public@db/verifier"
	cfg.ValkeyURL = "redis://valkey:6379"
	cfg.VerifierInternalURL = "http://eudi-verifier-core-internal:8080"
	cfg.InternalAPIToken = "test-token"
	cfg.HandoffEncKeyFile = "/keys/handoff.pem"
	cfg.WebhookSigningKeyFile = "/keys/webhook.pem"
	cfg.SessionDefaultTTL = 5 * time.Minute
	cfg.WebhookTimeout = 10 * time.Second
	cfg.RetryBaseDelay = 30 * time.Second
	cfg.RetryMaxAttempts = 8
	cfg.ConsumerPollEvery = time.Second
	cfg.SessionRateLimitPerKey = 50
	cfg.SessionRateLimitPerIP = 100
	cfg.SessionRateWindow = time.Minute

	err := cfg.Validate(validation.New())
	qt.Assert(t, qt.IsNil(err))
}

// TestConfigurationValidateRejectsBadURL asserts the "url" tag on
// VerifierInternalURL is load-bearing (a plain non-URL string must fail),
// distinguishing "missing" from "present but malformed".
func TestConfigurationValidateRejectsBadURL(t *testing.T) {
	cfg := NewConfiguration()
	cfg.ServiceName = "eudi-api-management"
	cfg.PostgresDSN = "postgres://management_public@db/verifier"
	cfg.ValkeyURL = "redis://valkey:6379"
	cfg.VerifierInternalURL = "not-a-url"
	cfg.InternalAPIToken = "test-token"
	cfg.HandoffEncKeyFile = "/keys/handoff.pem"
	cfg.WebhookSigningKeyFile = "/keys/webhook.pem"
	cfg.SessionDefaultTTL = 5 * time.Minute
	cfg.WebhookTimeout = 10 * time.Second
	cfg.RetryBaseDelay = 30 * time.Second
	cfg.RetryMaxAttempts = 8
	cfg.ConsumerPollEvery = time.Second
	cfg.SessionRateLimitPerKey = 50
	cfg.SessionRateLimitPerIP = 100
	cfg.SessionRateWindow = time.Minute

	err := cfg.Validate(validation.New())
	qt.Assert(t, qt.IsNotNil(err))
}
