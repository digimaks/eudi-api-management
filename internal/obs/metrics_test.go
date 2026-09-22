package obs

import (
	"strings"
	"testing"

	"github.com/VictoriaMetrics/metrics"
	"github.com/go-quicktest/qt"
)

// TestIncSessionCreatedEmitsCounter mirrors eudi-verifier-core's dumpMetrics
// idiom: assert the exact series name+labels the metric registry
// (VictoriaMetrics/metrics, the same registry Azugo serves at /metrics)
// actually recorded.
func TestIncSessionCreatedEmitsCounter(t *testing.T) {
	IncSessionCreated("same_device")

	dump := dumpMetrics(t)
	qt.Assert(t, qt.IsTrue(strings.Contains(dump,
		`management_api_sessions_created_total{flow="same_device"}`)))
}

func TestIncScopeDenialEmitsCounter(t *testing.T) {
	before := metrics.GetOrCreateCounter(MetricScopeDenialsTotal).Get()
	IncScopeDenial()
	after := metrics.GetOrCreateCounter(MetricScopeDenialsTotal).Get()

	qt.Check(t, qt.Equals(after-before, uint64(1)))
}

// TestMetricWebhookDeliveryTotalIsSingleSourced pins that internal/webhook's
// own MetricWebhookDeliveryTotal constant is the SAME string as this
// package's — not a second, independently-maintained literal (compile-time
// proof lives in webhook/consumer.go's `= obs.MetricWebhookDeliveryTotal`
// re-export; this just documents/locks the exact value so a future edit here
// can't silently drift).
func TestMetricWebhookDeliveryTotalIsSingleSourced(t *testing.T) {
	qt.Check(t, qt.Equals(MetricWebhookDeliveryTotal, "management_api_webhook_delivery_total"))
}

// dumpMetrics renders the shared VictoriaMetrics default registry (the same
// one Azugo serves at /metrics) so tests can assert on series without a
// running server — following eudi-verifier-core's precedent.
func dumpMetrics(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	metrics.WritePrometheus(&b, true)
	return b.String()
}
