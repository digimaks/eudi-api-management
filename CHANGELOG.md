# Changelog

Notable changes, newest first. Releases are git tags; this file says what each tag contains.

## Unreleased

### Changed

- **Go 1.27.4** (was 1.27.2), both in `go.mod` and as the image's default build toolchain
  (`ARG GO_VERSION` in the `Dockerfile`), and the framework moves to **azugo v0.50.2**, with
  `go-platform-kit` → v1.13.0, `go-dcql` → v0.0.4, `go-eudi-crypto` → v0.0.10, `go-eudi-rpcert` →
  v0.0.8, `go-verifier-helpers` → v0.0.6 and `go-eudi-trust` → v0.1.4. **Rebuild the image to pick
  this up.**
- **Request bodies the framework reads are held to 4 MiB.** A session or template request over
  that size is answered `413` with a problem document; the limit can be changed with
  `SERVER_MAX_REQUEST_BODY_SIZE`. Requests this service accepts are far smaller.

## v0.1.1

A security release. **The service now builds with Go 1.27.2**, and its libraries move to their Go 1.27.2
releases. The API, the configuration and the database are unchanged; one timing behaviour of the call
to the verifier engine changes with the framework (see *Changed*).

### Changed

- **Go 1.27.2** (was 1.27.0), both in `go.mod` and as the image's default build toolchain
  (`ARG GO_VERSION` in the `Dockerfile`). Go 1.27.2 fixes standard-library and `golang.org/x/net`
  vulnerabilities that this service's code reaches under 1.27.0: `govulncheck` found nine it calls,
  GO-2026-6603, -6605, -6607, -6608, -6610, -6611, -6612, -6613 and -6617, in `net/http`,
  `crypto/tls`, `net/textproto`, `mime/multipart` and `golang.org/x/net`. Under the new set it finds
  none. **Rebuild the image to pick the fixes up**; an image built before this change still carries
  them.
- **Libraries:** `go-dcql` → v0.0.3, `go-eudi-crypto` → v0.0.9, `go-eudi-rpcert` → v0.0.7,
  `go-verifier-helpers` → v0.0.5, `go-platform-kit` → v1.11.4, azugo → v0.40.0, `fasthttp` →
  v1.75.0, `go-redis` → v9.23.0, `VictoriaMetrics/metrics` → v1.44.1, `golang.org/x/crypto` →
  v0.58.0, `miniredis` (tests only) → v2.40.0, plus 39 indirect modules with them.
- **A call to `eudi-verifier-core` now stops at the inbound request's deadline.** From azugo v0.40.0
  the outbound client enforces the deadline of the request it was made for, where before a slow
  engine ran to completion and the deadline was only noticed afterwards. A call cut off this way
  answers the way an unreachable engine always has (*engine unavailable*). Nothing else in azugo
  v0.40.0 reaches this service: it sets no cookies, issues no redirects and implements no azugo
  cache.

### Notes

- `LICENSE` drops the boilerplate header that preceded the licence text (merged from the published
  repository). The licence itself is unchanged: EUPL-1.2.
- The image build now caches Go modules and compiled packages between builds. The binary is built by
  the same command with the same flags; only the build's layer order and caches changed.
- CI's linter moved to golangci-lint v2.14.0. The earlier release cannot read Go 1.27.2's compiled
  standard library and stops before linting anything.
- The gate is green on Go 1.27.2, with the `testhelpers` build tag as CI uses it: `go mod verify`,
  `go mod tidy -diff`, build, vet, `gofmt`, golangci-lint v2.14.0, `go test -race` with **0 races**,
  and all three fuzz targets for 30 seconds each with no failing input; `govulncheck` reports **no
  vulnerabilities found**.

## v0.1.0 — initial public release

**The tenant-facing API: a Relying Party's backend creates and authorizes verification sessions here, and collects the result by polling or signed webhook.**

It owns the tenant relationship, API-key authentication, session authoring (scope and intended-use
authorization), template CRUD, webhook delivery with retries, and rate limiting. It never speaks to a
wallet and mints no session itself: it authorizes the request and delegates the mint to the verifier
engine over a token-guarded, cluster-internal call.

It is a public error boundary — problem responses carry no internal source or chain, and attribute
values are redacted out of anything that leaves the process.

### Running it

The image entrypoint is `["/server", "web"]`, with `["/server", "health"]` as the healthcheck
command — a compose or orchestrator file that also passes `command: ["web"]` would append a second
argument. Every setting is an environment variable with a safe default where one is possible; the
README lists them, and any secret can be supplied as `<NAME>_FILE` pointing at a mounted file instead.

### What it needs

Go **1.27.0** to build. Libraries at this release:

`go-dcql` v0.0.2 · `go-eudi-crypto` v0.0.8 · `go-eudi-rpcert` v0.0.6 ·
`go-verifier-helpers` v0.0.4 · `go-platform-kit` v1.11.3 · `azugo.io/azugo` + `azugo.io/core` v0.38.1
