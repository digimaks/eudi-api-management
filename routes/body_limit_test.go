package routes

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// frameworkBodyLimit is the framework's default request body limit (4 MiB).
const frameworkBodyLimit = 4 << 20

// paddedSessionBody returns a JSON body of exactly size bytes that is a
// syntactically valid session request carrying a long padding string.
func paddedSessionBody(size int) []byte {
	const head = `{"pad":"`
	const tail = `"}`
	return []byte(head + strings.Repeat("a", size-len(head)-len(tail)) + tail)
}

func TestCreateSession_BodyOverFrameworkLimit_413(t *testing.T) {
	ta, app := newSessionsApp(t)
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook",
		mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name"))

	tc := ta.TestClient()
	resp, err := tc.Post("/api/v1/sessions", paddedSessionBody(frameworkBodyLimit+1024),
		tc.WithHeader(apiKeyHeader, apiKey), tc.WithHeader("Content-Type", "application/json"))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge))
	qt.Check(t, qt.IsTrue(bytes.HasPrefix(resp.Header.ContentType(), []byte("application/problem+json"))),
		qt.Commentf("content-type %q", resp.Header.ContentType()))
}

func TestCreateSession_BodyJustUnderFrameworkLimit_ReachesHandler(t *testing.T) {
	ta, app := newSessionsApp(t)
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook",
		mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name"))

	tc := ta.TestClient()
	resp, err := tc.Post("/api/v1/sessions", paddedSessionBody(frameworkBodyLimit-1024),
		tc.WithHeader(apiKeyHeader, apiKey), tc.WithHeader("Content-Type", "application/json"))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	// The body is read and parsed; the handler then refuses it for its own
	// reason (no presentation), which is not a 413.
	qt.Check(t, qt.Not(qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge)))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}
