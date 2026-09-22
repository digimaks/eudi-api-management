package routes

import (
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	mgmt "github.com/digimaks/eudi-api-management"
)

func testApp(t testing.TB) *azugo.TestApp {
	t.Helper()
	app := mgmt.TestApp(t)
	err := Init(app)
	qt.Assert(t, qt.IsNil(err))
	return azugo.NewTestApp(app.App)
}

func TestHealthzOK(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/healthz")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
}

// Dependencies are unreachable in the unit-test app, so readyz must fail
// closed with 503, never "ready by default".
func TestReadyzFailsClosedWhenDepsDown(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/readyz")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusServiceUnavailable))
}

func TestCorrelationHeaderEchoed(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Get("/healthz", tc.WithHeader("X-Correlation-ID", "01TESTCID"))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(string(resp.Header.Peek("X-Correlation-ID")), "01TESTCID"))
}
