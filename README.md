# eudi-api-management

The **client-facing** service of an EU Digital Identity Wallet **Relying Party (Verifier)** — the tenant API a Relying Party backend talks to. It creates verification sessions, authorizes each one against the client's registered scope, manages presentation templates and API keys, and returns the verified result over a signed webhook, by polling, or both — then lets that result expire, keeping no attribute value of its own.

It is the counterpart to `eudi-verifier-core`: the **session-authoring** side of the split. eudi-api-management owns the tenant relationship and everything a Relying Party touches; `eudi-verifier-core` owns everything the *wallet* touches. eudi-api-management never speaks to a wallet and mints no OpenID4VP session itself — it authorizes a create request and hands the actual mint to `eudi-verifier-core`'s cluster-internal API.

Attribute values are **forwarded once, then forgotten**: the decrypted verification result exists only transiently in memory and in one webhook or poll response, then TTLs out of Valkey. It never touches PostgreSQL, and never appears in a log, trace, metric, or error message (GDPR / data minimisation).

---

## Where it sits

`eudi-api-management` is the only service a Relying Party backend ever reaches. It owns the client registry and the tenant-facing API; it drives `eudi-verifier-core` over a token-guarded, cluster-internal transport to author sessions; it consumes the encrypted result handoff `eudi-verifier-core` produces and delivers it onward; and it shares one Valkey and one PostgreSQL with its siblings. The diagram below is the full intermediary deployment; in standalone-RP mode the "Relying Party backend" *is* the operator's own system.

```mermaid
flowchart LR
    RP["Relying Party backend<br/>(tenant / client)"]

    subgraph Fleet["verifier deployment"]
        direction TB
        MA["eudi-api-management<br/>(this service)<br/>tenant API + webhooks"]
        VC["eudi-verifier-core<br/>wallet-facing engine"]
        TCW["trust-cache worker<br/>keeps the cache warm"]
        VK[(Valkey<br/>handoff queue · respcode · retry state · trust cache)]
        PG[(PostgreSQL<br/>registry + session metadata + reports<br/>— NO attribute values)]
    end

    Wallet["EUDI Wallet<br/>(holder's device)"]

    RP -- "create session · poll · templates · API keys (X-API-Key)" --> MA
    MA -- "POST /internal/v1/sessions (bearer)" --> VC
    Wallet -- "GET request.jwt · POST response" --> VC
    MA -- "registry + session (EXECUTE-only procedures)" --> PG
    MA -- "consume handoff queue · redeem response_code · retry ZSET" --> VK
    VC -- "enqueue result JWE" --> VK
    MA -- "optional<br/>signed webhook (result JWE)" --> RP
    TCW -- "materialize anchors + status lists" --> VK
```

Division of labour: `eudi-api-management` owns the tenant relationship, API-key auth, session *authoring* (scope + intended-use authorization), template CRUD, webhook delivery + retries, and rate limiting. `eudi-verifier-core` owns everything the *wallet* touches — request signing, response processing, and the cryptographic verdict. The two meet at the token-guarded `POST /internal/v1/sessions` transport and the encrypted Valkey handoff queue that `eudi-verifier-core` writes and this service consumes.

---

## HTTP surface

Every `/api/v1` route sits behind the **X-API-Key** boundary and renders **RFC 9457 `application/problem+json`** with a stable machine `code` (`err:domain:reason`) — this is the public-error boundary (`PublicErrors=true`). Health probes are open.

| Method + path | Purpose | Notes |
|---|---|---|
| `POST /api/v1/sessions` | Create a verification session | Authorizes (DCQL scope, intended-use, pre-registered origins), then delegates the mint to `eudi-verifier-core`. **Rate-limited** per client id **and** per client IP. For `flow: dc_api` the response carries `dcApiResponseUri` — see the note below |
| `GET /api/v1/sessions/{sessionId}` | Poll state, value-free report, and — once released — the result | `?responseCode=` redeems the OpenID4VP §8.2 same-device code (single-use, sticky). `result` present only while `verified` **and** within the result TTL |
| `DELETE /api/v1/sessions/{sessionId}` | Cancel a pending / wallet-engaged session | Transition matrix is authoritative in the DB procedure; the internal `eudi-verifier-core` delete is best-effort after |
| `GET /api/v1/templates` | List the client's own presentation templates | Scoped to the caller (per-client isolation) |
| `POST /api/v1/templates` | Create a template | DCQL validated against the client's registered intended use at **write time** |
| `GET /api/v1/templates/{templateId}` | Fetch one template | Foreign / unknown both render `err:template:not-found` (404) — no existence leak |
| `DELETE /api/v1/templates/{templateId}` | Soft-delete a template | Same no-existence-leak 404 |
| `GET /healthz` | Liveness | 200 whenever the process is up |
| `GET /readyz` | Readiness (fail-closed) | 503 listing the failing component if Postgres or Valkey is unreachable |

The correlation id minted at session create rides every hop — into `eudi-verifier-core`'s internal API, through the pipeline, back out on the webhook — and is returned in `X-Correlation-ID`. Authentication failures (missing / malformed / unknown / wrong-secret / revoked key) all collapse to **one uniform 401** with no distinguishing detail — the wire must reveal nothing about *which* key is valid (no oracle).

### `dcApiResponseUri` — browser-mediated sessions only

In the browser-mediated flow the wallet hands its answer back to the **calling web page**, not to an endpoint of ours, so the page needs somewhere to post it. `POST /api/v1/sessions` with `"flow": "dc_api"` therefore returns `dcApiResponseUri` alongside `dcApiRequest`:

```json
{
  "sessionId": "bsw-Rg_hJlZxF75hwk0EIg",
  "state": "pending",
  "dcApiRequest": { "protocol": "openid4vp-v1-signed", "data": { "request": "eyJ…" } },
  "dcApiResponseUri": "https://verifier.example/wallet/t4H921rz-UYbtZF2IVi8Xw/response",
  "expiresAt": "2026-08-07T11:05:00Z"
}
```

It is **absent for the redirect-based flows**, where the wallet posts directly and the field would name an endpoint the caller has no business calling. The value is an opaque token-routed URL minted by the engine — it is deliberately **not** derived from `sessionId`, and the engine session id is never exposed. Pass it through unchanged.

A `dc_api` create for a client with **no registered origins** is refused up front with `err:client:originNotRegistered` (403) rather than delegated: the browser's calling origin is validated against that list before anything it returns is decrypted, so a client without one cannot use the flow at all. Origins are set through eudi-api-registration's `PUT /api/clients/{id}/allowed-origins`.

---

## Architecture

One application object (`App` in [`app.go`](app.go)) wires every dependency at startup and **fails closed** on any misconfiguration — an unreadable key file, a bad DSN, or a missing internal-API token stops the process from starting. The composed cryptographic work is all framework-free `go-eudi-*` and `go-verifier-helpers` code; algorithm policy lives only in the crypto library — there are no algorithm string literals here. Two background `core.Tasker`s (webhook consumer, expiry sweeper) start with the app.

```mermaid
flowchart TB
    subgraph App["App (app.go) — built once by New()"]
        direction TB
        Init["init(): RegisterReason (taxonomy) → platform.Setup (PublicErrors + redaction) →<br/>keys → Postgres pool (management_public) →<br/>registry + session stores → vcclient → Valkey →<br/>webhook consumer + sweeper (AddTask)"]
    end

    subgraph Routes["routes/ — HTTP handlers behind X-API-Key"]
        A["authmw.go<br/>argon2id · uniform 401 · client_id"]
        S["sessions.go<br/>create · poll · cancel"]
        T["templates.go<br/>CRUD + scope"]
        RL["ratelimit.go<br/>per-key · per-IP"]
        H["health · readyz"]
    end

    subgraph Internal["internal/ — service logic (framework-light)"]
        AK["apikeys<br/>mint / parse / verify"]
        SC["scope<br/>DCQL WithinScope"]
        VCC["vcclient<br/>eudi-verifier-core internal API"]
        RES["results<br/>decrypt + map handoff"]
        WH["webhook<br/>consumer · retrier · sweeper · signer"]
    end

    subgraph Data["data layer"]
        REG["registrydb<br/>registry.* procedures"]
        SDB["sessiondb<br/>session.* procedures"]
        VK[(Valkey<br/>handoff · respcode · retry)]
        PG[(PostgreSQL<br/>EXECUTE-only role)]
    end

    Routes --> App
    A --> AK
    S --> SC & VCC & RES
    App --> WH
    REG & SDB --> PG
    WH -- "drain queue · retry ZSET" --> VK
    RES -- "read payload · GETDEL respcode" --> VK
    S --> REG & SDB
    WH --> SDB
```

---

## Session lifecycle, end to end

A cross-device flow, from a client's create call to a delivered-and-forgotten result. The wallet steps all happen inside `eudi-verifier-core`; eudi-api-management's part is the authorization at the front and the delivery at the back.

```mermaid
sequenceDiagram
    participant RP as Relying Party
    participant MA as eudi-api-management
    participant VC as eudi-verifier-core
    participant VK as Valkey
    participant PG as PostgreSQL
    participant W as Wallet

    RP->>MA: POST /api/v1/sessions (X-API-Key)
    MA->>MA: apiKeyAuth (argon2id, constant-time) → client_id
    MA->>PG: resolve client · intended use · WRPRC (registry.* procedures)
    MA->>MA: DCQL WithinScope · origins · mint correlation id
    MA->>VC: POST /internal/v1/sessions (bearer + correlation)
    VC-->>MA: 201 {sessionId, walletUrl, qrPayload, expiresAt}
    MA-->>RP: 201 SessionCreated (state=pending)

    Note over W,VC: wallet runs the OpenID4VP flow against eudi-verifier-core
    VC->>VK: LPUSH vc:handoff:queue + result JWE (verified or failed)

    loop poll tick (HANDOFF_POLL_INTERVAL)
        MA->>VK: RPOP vc:handoff:queue
    end
    MA->>VK: GET vc:handoff:payload:{id} → decrypt result_jwe
    MA->>MA: build + sign detached-JWS webhook (zero plaintext after)
    MA->>RP: POST webhook (X-Payload-Signature)
    alt 2xx
        MA->>PG: session.set_webhook_state(delivered)
    else non-2xx / transient
        MA->>VK: ZADD mgmt:webhook:retry (backoff, bounded by result TTL)
    end

    RP->>MA: GET /api/v1/sessions/{id} (poll fallback)
    MA->>PG: state + report (claim NAMES only)
    MA->>VK: result (claim VALUES) — only while verified AND within TTL
```

---

## Authorizing a create request

`POST /sessions` never trusts the request's DCQL blindly — it is authorized against what the client is *registered* for before any session exists. The order is deliberate ([`routes/sessions.go`](routes/sessions.go)): resolve the target intended use, re-check it is not revoked, then scope-check, then origin-check, and only then mint. Every rejection is a precise problem code, never a value.

```mermaid
flowchart TB
    R(["POST /sessions (authenticated)"]) --> X1{"exactly one of<br/>templateId / dcqlQuery?"}
    X1 -- no --> B1["400 bad request"]
    X1 -- yes --> IU["resolve intended use (ARF TS5)<br/>intendedUseId required when > 1"]
    IU --> REV{"intended use revoked?"}
    REV -- yes --> B2["err:registrar:intended-use-revoked (422)"]
    REV -- no --> SCOPE{"DCQL within<br/>registered scope?"}
    SCOPE -- no --> B3["err:client:scope-exceeded (403)<br/>+ offending paths (never values)"]
    SCOPE -- yes --> ORIG{"redirect / webhook origins<br/>pre-registered?"}
    ORIG -- no --> B4["err:client:origin-not-registered (403)"]
    ORIG -- yes --> RID{"registrar identity on file<br/>(URL + identifier)?"}
    RID -- no --> B5["err:client:registrar-identity-required (422)<br/>+ the step that records it"]
    RID -- yes --> MINT["vcclient → eudi-verifier-core mint<br/>(clamped to SESSION_TTL)"]
    MINT --> OK(["201 SessionCreated"])
```

- **Intended use (ARF TS5).** `intendedUseId` selects the registrar-assigned intended use the request acts under; it is required once the client has more than one registered. A template pins its own intended use at creation, so a template request ignores the field. Resolution goes through `registry.get_wrprc_for_intended_use`, which distinguishes *unowned / unknown* (→ 404, no existence leak) from *owned but no current WRPRC* (→ graceful registrar-reference fallback — absence is never an error).
- **Scope** ([`internal/scope`](internal/scope/scope.go)). The DCQL query is parsed and OpenID4VP §6/§7-validated, then checked against the intended use's registered credentials via `go-dcql`'s `WithinScope`. The same check runs at **template create time** and again at **session create time** — a template valid when written can still fail create if its intended use was revoked in between.
- **Delegation** ([`internal/vcclient`](internal/vcclient/client.go)). Only once authorized does this service call `eudi-verifier-core`'s `POST /internal/v1/sessions`. eudi-api-management has **no** `create_session` grant — `eudi-verifier-core`'s internal API is the sole writer of the session row. Per-session `ttlSeconds` is honored but **clamped to `eudi-verifier-core`'s `SESSION_TTL`**; the returned `expiresAt` is the truth. A downstream problem is relayed intact (never collapsed to a bare 502). When the engine itself does not answer usably — unreachable, timed out, an undecodable answer — the caller gets `502 err:upstream:unavailable` titled *Verifier engine unavailable*, and the cause is written to the log line's `error.detail`.

---

## API keys and the no-oracle auth boundary

Client keys have the shape `vk_<prefix>_<secret>` — an 8-char Crockford-base32 public lookup prefix (indexed, safe to store) and a 32-char base64url secret (192 bits) the client keeps. Only the **argon2id** PHC hash of the secret is ever persisted (`registry.api_key.secret_hash`); the plaintext is returned exactly once at mint. [`internal/apikeys`](internal/apikeys/apikeys.go) is framework-free and fuzzed (`FuzzParseAPIKey`).

The [auth middleware](routes/authmw.go) is timing-flat by construction:

```mermaid
flowchart TB
    K(["X-API-Key presented"]) --> P["apikeys.Parse"]
    P -- "malformed" --> D1["verify raw value vs DummyPHC()"]
    P -- "well-formed" --> L["registry.get_client_by_key_prefix"]
    L -- "unknown prefix" --> D2["verify secret vs DummyPHC()"]
    L -- "known" --> V["verify secret vs stored hash"]
    L -- "infra error" --> E["500 (fail closed, distinct)"]
    D1 & D2 & V --> J{"ok AND known AND active AND not revoked?"}
    J -- no --> U["401 err:client:unauthorized<br/>(one uniform body)"]
    J -- yes --> S["set client_id → next()"]
```

`apikeys.Verifier.Verify` runs **exactly once** per request, always against a full argon2id derive — a malformed key or unknown prefix is verified against a fixed `DummyPHC()` so it pays the same cost as a wrong secret on a real key. Only **successful** verdicts are ever cached (5 min, 1024 entries, constant-time secret compare), so no failure is ever served fast: "wrong secret", "unknown prefix", and "malformed key" stay mutually timing-indistinguishable, and repeated guessing cannot enumerate valid prefixes. The one path that is *not* a 401 is a genuine registry infrastructure failure — a distinct 500, because the no-oracle rule is about not leaking *which key is valid*, not about hiding that the service is down.

---

## Webhook delivery: consume, sign, forward, forget

[`internal/webhook`](internal/webhook/consumer.go) is the sole reader of the handoff queue `eudi-verifier-core` writes. A background `Consumer` drains `vc:handoff:queue` (RPOP) on every poll tick plus anything the `Retrier` marks due; a `Sweeper` on a fixed 30 s cadence is the only path that ever notifies a client of an **expired** session (nothing else would — an expired session never produced a handoff envelope). A **poll-only** session (no webhook configured — neither a per-request `webhookUrl` nor a registered default) is never enqueued for delivery by `eudi-verifier-core`: its result is buffered for polling only, and neither the consumer nor the sweeper attempts a delivery or records a failure for it.

```mermaid
flowchart LR
    Q["vc:handoff:queue<br/>(eudi-verifier-core writes)"] -->|"RPOP"| C["Consumer.processOne"]
    C -->|"GET payload → decrypt result_jwe"| B["build + sign<br/>(detached JWS)"]
    B -->|"POST"| RP["client webhook"]
    RP -->|"2xx"| OK["session.set_webhook_state(delivered)"]
    RP -->|"non-2xx"| SCH["Retrier.Schedule<br/>ZADD mgmt:webhook:retry"]
    SCH -->|"due"| C
    C -.->|"payload missing / undecryptable /<br/>attempts exhausted / past TTL"| F["terminal: failed<br/>err:webhook:delivery-failed + alert"]
```

- **Detached JWS** ([`signer.go`](internal/webhook/signer.go)). The body is signed with the operator `webhook-signing` key (RFC 7515 App. F detached form — `<protected>..<sig>` in `X-Payload-Signature`); the client reattaches its own copy of the body and verifies against the JWKS `eudi-verifier-core` publishes at `/.well-known/verifier-jwks.json`. `alg` is derived from the key's curve (ES256), never a caller literal.
- **Backoff bounded by the result TTL** ([`retry.go`](internal/webhook/retry.go)). Delay is `base × 2^attempt`; the schedule is a Valkey ZSET (`mgmt:webhook:retry`) with due-claim via `ZRem`-returns-1 (multi-replica safe, no lock). Retries live **inside** the result TTL — a next attempt past `expiresAt`, or past `WEBHOOK_RETRY_MAX_ATTEMPTS`, is terminal. There is no DB fallback for the payload.
- **Fail-closed edges.** A payload already gone at pop (session expired first) or an undecryptable `result_jwe` is an **immediate** terminal failure — never a silent drop. A *transient* read error re-enqueues the id instead. Terminal failure sets `webhook_state=failed` and increments the alert metric — those two effects only; the Valkey TTL remains the sole purge.
- **Values never linger.** The decrypted plaintext buffer is zeroed the moment it is mapped onto the DTO; the response/webhook body is the only place values land again, and bodies are never logged or inspected.

---

## Forward-and-delete: results and polling

Webhook delivery and polling read the **same** encrypted handoff payload; a successful webhook does **not** delete it. [`internal/results.Fetch`](internal/results/results.go) stays available as a fallback for the whole result-TTL window (≤ 24 h) — a client that missed or dropped the webhook can still poll `GET /sessions/{id}` for `result` until the Valkey TTL elapses — and a **poll-only** session (no webhook configured) relies on this path exclusively.

```mermaid
flowchart TD
    P["GET /sessions/{id}"] --> ST{"state?"}
    ST -- "pending / wallet_engaged" --> R0["state only<br/>(no report yet)"]
    ST -- "terminal" --> REP["report (claim NAMES) from Postgres"]
    REP --> VR{"verified?"}
    VR -- no --> DONE["report + failure"]
    VR -- yes --> SD{"same_device?"}
    SD -- "no" --> FETCH["results.Fetch → result (claim VALUES)"]
    SD -- "yes" --> RC{"responseCode redeemed?<br/>(GETDEL vc:respcode, sticky)"}
    RC -- yes --> FETCH
    RC -- no --> HOLD["hold result until redeemed"]
    FETCH -->|"payload TTL elapsed"| GONE["nil result — report still stands"]
```

The report (claim **names** and per-check outcomes) is durable in PostgreSQL and stands on its own once the value payload is gone. For a `same_device` session, `result` is gated on a single-use OpenID4VP §8.2 `response_code` redemption (`GETDEL vc:respcode:{code}` + client-ownership check); redemption is sticky (`CodeRedeemedAt`), so the code is supplied once and every later poll releases the result with no code at all. A corrupt or undecryptable payload is an error, never an empty success.

---

## State and data model

**No attribute value is ever persisted.** PostgreSQL holds the client **registry** and **session** metadata + verification reports (claim-**name**-only domain), accessed exclusively through `SECURITY DEFINER` procedures via a JSONB envelope ([`internal/registrydb`](internal/registrydb/db.go), [`internal/sessiondb`](internal/sessiondb/db.go)). The service never touches tables directly; its role `management_public` has `EXECUTE`-only grants, and client isolation is enforced *inside* the procedures — a call with another client's id returns `registry:not_found` (404, no existence leak), not 403.

Valkey keys read / written by this service (all TTL-bounded). When `VALKEY_KEY_PREFIX` is set every key below is stored as `<prefix>:<key>`; the names themselves are the contract shared with `eudi-verifier-core` and never change:

| Key | Value | Role |
|---|---|---|
| `vc:handoff:queue` | session ids awaiting delivery | **read** (RPOP-drain); re-`LPUSH` only on a transient payload-read error |
| `vc:handoff:payload:{id}` | encrypted result JWE (`eudi-verifier-core` writes) | **read-only** |
| `vc:respcode:{code}` | → session id (§8.2 response_code, `eudi-verifier-core` writes) | **read** (`GETDEL`, exactly-once redemption) |
| `mgmt:webhook:retry` | ZSET of due retries (member = session id, score = next-attempt unix) | write (claim via `ZRem`) |
| `mgmt:webhook:attempts:{id}` | per-session attempt counter | write (TTL = time left to result TTL) |

`vc:*` keys are the cross-service handoff contract (`handoffwire`); `mgmt:webhook:*` keys are owned entirely by this service's webhook package. The `registry` and `session` schemas and the `management_public` role are provisioned by SQL migrations.

---

## Keys

Two operator keys, shared with `eudi-verifier-core` (same file, same fixed key ids — the JWKS `kid` is the wire contract), supplied as PEM files:

| Key ID | Purpose |
|---|---|
| `handoff-enc` | Decrypts the result JWE `eudi-verifier-core` enqueued (ECDH-ES + A256GCM to the operator handoff key) |
| `webhook-signing` | Detached-JWS signature over every webhook body; the public half is published by `eudi-verifier-core` at `/.well-known/verifier-jwks.json` so clients can verify |

This service serves no JWKS of its own — it *consumes* keys `eudi-verifier-core` owns the public side of.

### Key generation

`handoff-enc` is a self-generated operator key — no CA, no CSR. It is an **EC P-256** key (the HAIP 1.0 / ECCG baseline) used for `ECDH-ES` key agreement. `openssl genpkey` emits a PKCS#8 PEM, which the key loader accepts (a SEC1 `-----BEGIN EC PRIVATE KEY-----` file works too); a non-EC or non-allow-listed curve is rejected at startup, fail-closed.

```bash
# handoff-enc — EC P-256 private key, PKCS#8 PEM.
# Point HANDOFF_ENC_KEY_FILE at this file.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out handoff-enc.key.pem
```

> **Note — this key is shared with `eudi-verifier-core`.** It is one operator secret, not two. Generate it **once** and mount the **same** file into both services: `eudi-verifier-core` encrypts the result JWE to it, and eudi-api-management decrypts with it. If the two files differ, decryption fails closed — an undecryptable payload is an error, never an empty success. Keep the file out of version control and supply it as a mounted secret.

---

## Error taxonomy

Registered once in [`app.go`](app.go) before `platform.Setup`; every code this service emits is `err:domain:reason`. The wire spelling of a DB-sourced reason mirrors the procedure's own (underscore) form.

| Code | Status | Raised when |
|---|---|---|
| `err:client:unauthorized` | 401 | Any auth failure — one uniform body, no oracle (built-in reason) |
| `err:client:not-registered` | 403 | Key valid but the client is not active |
| `err:client:scope-exceeded` | 403 | DCQL requests attributes outside the registered intended use (detail = offending paths) |
| `err:client:origin-not-registered` | 403 | `redirectUri` / `webhookUrl` origin not pre-registered for the client |
| `err:client:intended-use-required` | 422 | `intendedUseId` omitted with more than one registered intended use (ARF TS5) |
| `err:client:registrar-identity-required` | 422 | The client's stored registration has no usable registrar identity (registrar URL + assigned identifier), so the registration reference every wallet request carries cannot be built. Record it with the registration API's `PUT /api/clients/{id}/registrar-identity`; the detail names the unusable field and that step |
| `err:registrar:intended-use-revoked` | 422 | Target intended use is revoked |
| `err:upstream:unavailable` | 502 | `eudi-verifier-core` did not answer usably — unreachable, timed out, or an answer that could not be decoded. Title "Verifier engine unavailable"; the cause is in the log line's `error.detail`, never in the response |
| `err:session:not_cancellable` | 409 | Cancel attempted on a terminal session |
| `err:session:not_found` | 404 | Unknown / cross-client session id |
| `err:template:not-found` | 404 | Unknown / cross-client template id |
| `err:webhook:delivery-failed` | 502 | Terminal webhook delivery failure (recorded on the session) |

---

## Configuration

Standard fleet env (`SERVER_URLS`, `SERVICE_NAME`, `ENVIRONMENT`, `LOG_*`, `METRICS_ENABLED`, `OTEL_*`, `RATELIMIT_*`) comes from the shared base configuration, plus:

| Env var | Default | Meaning |
|---|---|---|
| `POSTGRES_DSN` | — (required) | PostgreSQL DSN — connects as the EXECUTE-only `management_public` role. Secret: supports the `POSTGRES_DSN_FILE` convention (an explicit plain `POSTGRES_DSN` still overrides it) |
| `VALKEY_URL` | — (required) | Shared Valkey/Redis URL (handoff queue, respcode, retry state): `redis://` or `rediss://` (TLS), optional `user[:password]@`, `/N` database index, `?skip_verify=true` on `rediss://` |
| `VALKEY_PASSWORD` | *(unset)* | Password for the Valkey user; overrides one embedded in `VALKEY_URL`. Also readable via the `VALKEY_PASSWORD_FILE` indirection so a platform can mount it. Secret — never logged |
| `VALKEY_KEY_PREFIX` | *(unset)* | Prepended as `<prefix>:` to every Valkey key this service reads or writes (a trailing `:` in the value is tolerated). Required when the instance confines the user's ACL to a key pattern; **must equal `eudi-verifier-core`'s**, or the handoff queue and payloads it writes are invisible here and no webhook is ever delivered |
| `VERIFIER_INTERNAL_URL` | — (required) | `eudi-verifier-core`'s base URL for the internal session API (cluster-internal) |
| `INTERNAL_API_TOKEN` | — (required) | Bearer token authenticating this service to `eudi-verifier-core`'s `/internal` routes — prefer the `_FILE` form |
| `HANDOFF_ENC_KEY_FILE` | — (required) | PEM path — result-JWE decryption key (must match `eudi-verifier-core`'s) |
| `WEBHOOK_SIGNING_KEY_FILE` | — (required) | PEM path — webhook signing key (must match `eudi-verifier-core`'s) |
| `SESSION_DEFAULT_TTL` | `5m` | Session TTL when the request omits `ttlSeconds` (request range 60–3600 s; clamped to `eudi-verifier-core`'s `SESSION_TTL`) |
| `WEBHOOK_TIMEOUT` | `10s` | Per-POST webhook delivery timeout |
| `WEBHOOK_RETRY_BASE_DELAY` | `30s` | First backoff delay — doubled per attempt, capped by the result TTL |
| `WEBHOOK_RETRY_MAX_ATTEMPTS` | `8` | Retry-attempt bound (independent of the TTL clamp) |
| `HANDOFF_POLL_INTERVAL` | `1s` | Handoff-queue drain tick |
| `SESSION_RATE_LIMIT_PER_KEY` | `50` | `POST /sessions` limit per authenticated client id, per window |
| `SESSION_RATE_LIMIT_PER_IP` | `100` | `POST /sessions` limit per client IP, per window |
| `SESSION_RATE_WINDOW` | `1m` | Rate-limit window for both dimensions |

**TLS is selected by the URL scheme.** `rediss://…` connects over TLS; `redis://…` does not. `skip_verify=true` only relaxes certificate verification on a `rediss://` URL — on a `redis://` URL the client rejects it outright (`redis: unexpected option: skip_verify`) rather than silently upgrading the connection. Earlier Azugo versions did treat `skip_verify=true` as an implicit request for TLS; that side-effect is fixed from **Azugo v0.37** onwards, so a TLS endpoint must always be addressed as `rediss://`.

---

## Metrics

Served on `/metrics`. Every label value comes from a **closed set** — never a session id, a client id, or anything derived from wallet/client input.

| Metric | Labels | Meaning |
|---|---|---|
| `management_api_sessions_created_total` | `flow` (`same_device`\|`cross_device`\|`dc_api`) | Successful (201) session creations |
| `management_api_scope_denials_total` | — | Requests rejected for `scope-exceeded` (create + template) |
| `management_api_webhook_delivery_total` | `outcome` (`delivered`\|`failed`) | Webhook delivery outcomes — `failed` is the terminal-failure alert signal |

---

## Directory layout

```
eudi-api-management/
├── app.go, config.go, redaction.go        — App container, config, PII redaction (+ error taxonomy in app.init)
├── testing.go                             — //go:build testhelpers harness (TestApp, fakes, miniredis)
├── cmd/server/                            — CLI entrypoint (web, health subcommands)
├── routes/                                — HTTP handlers behind X-API-Key
│   ├── authmw.go       — argon2id auth · uniform 401 · client_id scoping
│   ├── sessions.go     — create (authorize → delegate) · poll · cancel
│   ├── templates.go    — template CRUD + write-time scope
│   ├── ratelimit.go    — per-key + per-IP limiters on POST /sessions
│   ├── health.go       — /healthz · /readyz (fail-closed)
│   └── router.go       — route registration (auth-gated /api/v1 group)
└── internal/
    ├── api/            — hand-written DTOs + contract-parity test (OpenAPI 3.1)
    ├── apikeys/        — mint / parse / verify (argon2id, timing-flat, fuzzed)
    ├── scope/          — DCQL WithinScope enforcement (err:client:scope-exceeded)
    ├── vcclient/       — eudi-verifier-core internal session API client (sole mint path)
    ├── results/        — decrypt + map handoff payload (forward-and-delete reader)
    ├── webhook/        — consumer · retrier · sweeper · detached-JWS signer
    ├── registrydb/     — registry-schema SECURITY DEFINER procedure calls
    ├── sessiondb/      — session-schema procedure calls (poll / cancel / webhook state)
    └── obs/            — metric name constants + helpers
```

---

## Development

`testing.go` is `//go:build testhelpers`-gated so the production binary's dependency closure excludes the in-memory Valkey (miniredis / gopher-lua) test tree. **Any** command that touches `_test.go` files must carry the tag — always use the Makefile targets, never bare `go test`:

```bash
cd eudi-api-management
make build        # prod build — no tag; matches the Dockerfile + shipped binary
make test         # go test -tags testhelpers -race ./...   (CI: cgo available)
make test-fast    # same, no -race (local dev without cgo)
make vet          # go vet -tags testhelpers ./...   (vet type-checks _test.go too)
make lint         # golangci-lint run --build-tags testhelpers

# Fuzz the untrusted-input parser boundaries:
go test -tags testhelpers -run '^$' -fuzz '^FuzzParseAPIKey$'   -fuzztime 30s ./internal/apikeys/
go test -tags testhelpers -run '^$' -fuzz '^FuzzDecodeEnvelope$' -fuzztime 30s ./internal/webhook/
go test -tags testhelpers -run '^$' -fuzz '^FuzzCreateSessionBody$' -fuzztime 30s ./routes/
```

The unit suite runs entirely against in-process fakes: an in-memory Valkey (miniredis), and fake `registrydb` / `sessiondb` stores in place of Postgres, with `eudi-verifier-core`'s internal API stubbed by an `httptest.Server`. `TestApp` builds a fully wired `App` against these seams. The PG-backed stores are covered separately by `MGMT_TEST_PG_DSN`-gated integration tests and a compose-stack SQL role-leak suite. The wire DTOs are hand-written rather than generated, because the contract is OpenAPI 3.1 and the generator is 3.0-only.

---

## Security invariants

- **No attribute value anywhere durable** — the decrypted result lives only in memory and one response/webhook body, then TTLs out of Valkey; never in PostgreSQL, logs, traces, metrics, or error text. The plaintext buffer is zeroed after mapping; redaction is extended before any new struct is logged.
- **No existence leak** — a cross-client or unknown session / template / key reads as 404 (or the uniform 401 for keys), never 403; client isolation is enforced inside the DB procedures, not just the handler.
- **Timing-flat auth** — one argon2id derive per request, successes-only cache, constant-time compare; "wrong secret", "unknown prefix", and "malformed key" are mutually indistinguishable (no oracle).
- **Fail closed** — an undecryptable payload, a downstream problem, an exhausted retry, a missing handoff payload, or a bad config all fail with a precise code; a corrupt ciphertext is never an empty success.
- **Crypto policy centralized** — signing/encryption algorithms live only in `go-eudi-crypto` (ECCG allow-lists); `alg` is derived from the key, never a literal. (argon2id, a hash-at-rest KDF, is used directly — it is not a JOSE/COSE signing algorithm.)
- **Contract-first** — the OpenAPI contract changes before handler code; parity is test-enforced.
- **Untrusted-input parsers are fuzzed** — API keys and the cross-service handoff envelope must not panic on malformed input.

---

## Known limitations

- **Session creation depends on `eudi-verifier-core`.** eudi-api-management authorizes and then delegates the mint; if `eudi-verifier-core`'s internal API is unreachable, `POST /sessions` returns a relayed 502 (fail closed). This is deliberately **not** a `/readyz` dependency — polling and webhook delivery keep working while session creation degrades per-request.
- **Per-session `ttlSeconds` is clamped to `eudi-verifier-core`'s `SESSION_TTL`.** Promising a client the contract's full 3600 s range requires `SESSION_TTL ≥ 1h` on the deployment; otherwise the create response's `expiresAt` is the truth.
- **DTOs are hand-written.** `oapi-codegen` does not yet fully support OpenAPI 3.1 (it drops `WebhookPayload` and collapses `Template`'s `allOf`), so DTOs live in `internal/api/types.go`, kept honest by a contract-parity test. Swap to a 3.1-capable generator later without an interface change.
- **`transactionData`** (OpenID4VP `transaction_data`) is accepted in the contract but is a phase-2 concern.
- **Single-node key/value store only — no Redis Cluster.** The service uses one Redis-protocol endpoint (`VALKEY_URL`) with the standard single-node client and only ordinary commands (`SET`/`GET`/`GETDEL`/`RPOP`/`LPUSH`/`ZADD`/`ZREM`/`EXPIRE`) — so a non-clustered Redis OSS instance works interchangeably with Valkey. Redis Cluster is not supported (the client is not cluster-aware, and the fleet-shared handoff keys assume a single slot).
```

## License

EUPL-1.2 — see [`LICENSE`](LICENSE).
