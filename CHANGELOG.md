# Changelog

Notable changes, newest first. Releases are git tags; this file says what each tag contains.

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
