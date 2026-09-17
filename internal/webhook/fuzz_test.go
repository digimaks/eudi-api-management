package webhook

import "testing"

// FuzzDecodeEnvelope feeds arbitrary bytes through decodeEnvelope — the
// json.Unmarshal into handoffwire.Envelope that Consumer.processOne calls on
// every payload popped from Valkey. The envelope crosses the
// eudi-verifier-core/eudi-api-management service boundary, and every parser of untrusted
// input must have a fuzz target and must never panic on malformed input — this
// package trusts eudi-verifier-core to be the only writer, but a fuzz target
// defends against a corrupted/adversarial payload regardless.
func FuzzDecodeEnvelope(f *testing.F) {
	f.Add([]byte(`{"version":1,"session_id":"s1","client_id":"c1","correlation_id":"corr","webhook_url":"https://x","result_jwe":"a.b.c.d.e","enqueued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T01:00:00Z"}`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"version":"not-a-number"}`))
	f.Add([]byte(`{"expires_at":"not-a-time"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"result_jwe":12345}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		env, err := decodeEnvelope(raw)
		if err != nil {
			if env != nil {
				t.Fatalf("decodeEnvelope returned a non-nil envelope alongside an error: %v", err)
			}
			return
		}
		if env == nil {
			t.Fatalf("decodeEnvelope returned (nil, nil)")
		}
		// Touch every field a downstream caller (Consumer.processOne,
		// Deliverer.buildPayload) reads — must never panic regardless of what
		// arbitrary bytes decoded into these fields.
		_ = env.Version
		_ = env.SessionID
		_ = env.ClientID
		_ = env.CorrelationID
		_ = env.WebhookURL
		_ = env.ResultJWE
		_ = env.EnqueuedAt
		_ = env.ExpiresAt
	})
}
