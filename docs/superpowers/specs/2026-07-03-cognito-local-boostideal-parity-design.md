# cognito-local ↔ Boost Ideal Parity — Design

> **Status:** DRAFT — awaiting user approval (brainstorming gate).
> **Date:** 2026-07-03. **Branch:** `m2m-oauth2-support`. **Fork HEAD:** `v5.3.0-7-ge3086e7`.
> **Source requirements:** `docs/requirements/boostideal-parity-requirements.md`.
> **Grounding investigations:**
> - `docs/investigation/2026-07-03-mfa-challenge-current-state.md`
> - `docs/investigation/2026-07-03-target-registration-and-services.md`
> - `docs/investigation/2026-07-03-p0-image-bump-infra.md`

This design covers **everything code-side** in the parity doc. Because it spans four
independent subsystems plus a shared prerequisite, it is **decomposed into five units**,
each of which gets its own implementation plan (`writing-plans`) and its own
spec→plan→implement→verify cycle. This document is the umbrella design and the detailed
design for Units 0 and 1 (the "start now" items); Units 2–4 are designed to the level
needed to validate the decomposition and are refined in their own specs when reached.

---

## Decisions locked in (from scoping)

| Decision | Choice | Rationale |
|---|---|---|
| Scope | Everything code-side (P0 + foundation + P1 + P3 + P2) | User: "everything!" |
| Sequencing | Unit 0 → 1 → 2 → 3 → 4; decomposed, per-unit plans | Foundation unblocks P1/P2; ship value incrementally |
| WebAuthn depth | **Test-oriented** emulation (no real FIDO2 attestation/assertion crypto) | Matches how cognito-local already fakes keys/SMS OTP; clients are integration tests |
| Missing SDK types | **Hand-author** minimal TS types in the target files | aws-sdk pinned at v2.1145.0 (2022); a bump has wide blast radius across every target |
| Cross-repo P0 | Edit all three repos directly, separate commits per repo | All available locally |
| Test convention | Follow the **repo's** convention: `vi.fn()` mock-service unit tests (`src/targets/*.test.ts`) + real-SDK integration tests (`integration-tests/aws-sdk/*.test.ts`) | Every existing target test uses it; global CLAUDE.md "no mocks" rule is overridden by the concrete repo pattern here |

> **Note on the CLAUDE.md mock rule:** the global instructions forbid mocks, but this
> repo's established and only unit-test pattern for targets is `vi.fn()`-backed mock
> services. We match surrounding code (unit test with mocks **and** an integration test
> with the real SDK for each behavior). Flag for the user if they'd rather integration-only.

---

## Unit map & build order

| # | Unit | Priority | Depends on | Size | Repos touched |
|---|---|---|---|---|---|
| 0 | Docker image tag bump | P0 | — | XS | cognito-local, boostideal, deploy |
| 1 | Challenge/session store (foundation) | prerequisite | — | S | cognito-local |
| 2 | Forced `MFA_SETUP` enrollment | P1 | Unit 1 | L | cognito-local |
| 3 | Sign-out + admin MFA preference | P3 | — (independent) | S | cognito-local |
| 4 | WebAuthn / passkeys | P2 | Unit 1 | XL | cognito-local |

Unit 3 is independent of the others and could be built at any point; it is sequenced
after Unit 2 only so the harder challenge work lands first. Units 0 and 1 have no
dependencies and start immediately.

---

## Unit 0 — Docker image tag bump (P0)

**Problem.** The pinned integration-test image `cognito-local:5.1.0-m2m-fix` is a
*misleading tag* — fork HEAD is really upstream **v5.3.0** and already contains every
v5.2.0+ MFA feature. The tag string just lies about the version. The image is
**local-build only** (no registry publish), so tag and consumers must move in lockstep.

**Change set.**
1. `cognito-local/Taskfile.yml:5` — `TAG: 5.1.0-m2m-fix` → `TAG: 5.3.0-m2m`.
   (`docker:build`, lines 8–11, already builds `{{.IMAGE}}:{{.TAG}}`.)
2. `boostideal/dev/docker/docker-compose.integration_tests.yaml:213` (service
   `it-cognito-local`) — `image: cognito-local:5.1.0-m2m-fix` → `cognito-local:5.3.0-m2m`.
3. `deploy-aws-production-enablement/dev/boostideal/local/docker-compose.core.yaml:101`
   (service `cognito-local`) — same bump.
4. `deploy-aws-production-enablement/dev/boostideal/local/docker-compose.e2e.yaml:102`
   (service `cognito-local`, container `e2e-cognito-local`) — same bump; also fix the
   stale comment at `:96` ("Built from: /tmp/cognito-local").
5. Doc mentions for consistency: `cognito-local/docs/requirements/boostideal-parity-requirements.md:10,22`;
   deploy onboarding docs `00-lay-of-the-land.md:62`, `10-run-localprod.md:41,81`.
6. In boostideal: remove any `SetUserPoolMfaConfig` test-skip / "real-AWS-only" note now
   that the bumped image supports it.

**Data flow.** No code path changes. All three compose services expose container port
9229 with a `/health` healthcheck; only the image tag string changes.

**Testing / verification.**
- `task docker:build` in cognito-local produces `cognito-local:5.3.0-m2m`.
- Bring up each compose file; assert the `cognito-local` service passes its healthcheck.
- Run boostideal's integration test that calls `SetUserPoolMfaConfig` — it must now return
  200 instead of the v5.1.0 500 (`Unsupported x-amz-target`).

**Error handling.** Because the image is local-build-only, a consumer bumped before the
image is rebuilt will fail to pull. Commit order: rebuild image locally first, then land
the Taskfile + compose bumps together per repo.

**Commits.** One GPG-signed commit per repo (cognito-local, boostideal, deploy).

---

## Unit 1 — Challenge/session store (foundation)

**Problem.** There is no challenge/session store. Every challenge returns a throwaway
`Session: uuid()` that is *never validated* on return; user correlation is smuggled through
`ChallengeResponses.USERNAME` (`respondToAuthChallenge.ts:97-107`). `MFA_SETUP` and
`WEB_AUTHN` both need real server-side state keyed by `Session` (which challenge is in
flight, the in-progress software-token secret, the target user/pool). This is also the fix
for upstream Issue #392 (MFA-challenge Session UUID).

**Design.** Add an in-memory, TTL'd store modeled exactly on the existing
`src/oauth2/authorizationCodeStore.ts` (same `Map` + `expiresAt` + `create`/`consume`
shape), but with a `peek`/`get` that does **not** consume (multi-step flows read the
session repeatedly before finalizing).

New file `src/services/challengeStore.ts` (a service, wired into the `Services` container
in `src/server/defaults.ts` and the mock container in `src/__tests__/`):

```ts
export type ChallengeName =
  | "SMS_MFA" | "SOFTWARE_TOKEN_MFA" | "SELECT_MFA_TYPE"
  | "NEW_PASSWORD_REQUIRED" | "MFA_SETUP" | "WEB_AUTHN";

export interface ChallengeSession {
  challengeName: ChallengeName;
  userPoolId: string;
  clientId: string;
  username: string;
  // in-progress state carried across steps:
  softwareTokenSecret?: string;   // for MFA_SETUP TOTP association
  webAuthnChallenge?: string;     // for WEB_AUTHN
}

export interface ChallengeStore {
  create(data: ChallengeSession): string;                 // returns Session id (uuid)
  get(session: string): ChallengeSession | null;          // non-consuming, TTL-checked
  update(session: string, patch: Partial<ChallengeSession>): void;
  consume(session: string): ChallengeSession | null;      // read + delete (on finalize)
}
```

- TTL: mirror Cognito's ~3-minute challenge window (constant, documented). In-memory only;
  it does **not** survive process restart — acceptable for a local emulator, matches
  `AuthorizationCodeStore`. Documented explicitly.
- **Full migration, no dual paths** (per the no-tech-debt rule): every existing challenge
  producer (`SMS_MFA`, `SOFTWARE_TOKEN_MFA`, `SELECT_MFA_TYPE`, `NEW_PASSWORD_REQUIRED`) is
  switched to create a real session via the store, and `RespondToAuthChallenge` is switched
  to resolve the user from the session as the source of truth. `ChallengeResponses.USERNAME`
  remains an accepted *input* (AWS clients send it) but is **validated against** the
  session's username rather than being the correlation key. The old "Session is opaque,
  correlate via USERNAME" behavior is deleted, not kept alongside.

**Components.**
- `src/services/challengeStore.ts` — the store (+ `ChallengeSession`/`ChallengeName` types).
- `src/services/index.ts` — add `challengeStore: ChallengeStore` to `Services`.
- `src/server/defaults.ts` — construct and inject it.
- `src/__tests__/mockChallengeStore.ts` — `newMockChallengeStore()` for target unit tests.
- Migrate `initiateAuth.ts` + `respondToAuthChallenge.ts` session creation/validation to
  the store (no behavior change for existing challenges; sessions become meaningful).

**Testing.**
- Unit: `src/services/challengeStore.test.ts` — create/get/update/consume, TTL expiry
  (via `ClockFake`), consume-after-consume returns null.
- Regression: existing `respondToAuthChallenge.test.ts` / `initiateAuth.test.ts` updated to
  assert the returned `Session` round-trips through the store.
- Integration: existing `integration-tests/aws-sdk/respondToAuthChallenge.test.ts` must
  still pass (SMS/software-token challenges) — proves the migration is behavior-preserving.

**Error handling.** Unknown/expired session on `RespondToAuthChallenge` → `NotAuthorizedError`
(AWS returns `NotAuthorizedException: Invalid session ...`). Session/username mismatch →
`NotAuthorizedError`.

---

## Unit 2 — Forced `MFA_SETUP` enrollment (P1)

**Problem (the "critical parity gap").** A brand-new user in an `MfaConfiguration=ON` pool
who has not enrolled must be driven through TOTP enrollment on first login. Today four sites
block this (see investigation). Depends on Unit 1's session store.

**Change sites.**
1. **`initiateAuth.ts:122-149` (`verifyMfaChallenge`)** — when `methods.length === 0` and
   the pool forces MFA (`MfaConfiguration === "ON"`, or `OPTIONAL` per AWS rules), replace
   `throw new NotAuthorizedError()` with a returned `MFA_SETUP` challenge: create a
   `challengeStore` session (`challengeName: "MFA_SETUP"`, user/pool/client), respond with
   `ChallengeName: "MFA_SETUP"`, `Session`, and `ChallengeParameters` including
   `MFAS_CAN_SETUP: '["SOFTWARE_TOKEN_MFA"]'` (AWS shape).
2. **`associateSoftwareToken.ts:28-32`** — replace the Session rejection with a Session
   path: look up the challenge session, `generateSecret()`, store the secret on the session
   via `challengeStore.update` (not yet on the user — enrollment isn't final), return
   `{ SecretCode, Session }`.
3. **`verifySoftwareToken.ts:34-38`** — replace the Session rejection with a Session path:
   read the session's `softwareTokenSecret`, `verify(secret, UserCode)`, on success persist
   `SoftwareTokenMfaConfiguration: { Secret, Verified: true }` + add `SOFTWARE_TOKEN_MFA` to
   the user's `UserMFASettingList` via `saveUser`, return `{ Status: "SUCCESS", Session }`
   (a fresh session id for the follow-up `RespondToAuthChallenge`).
4. **`respondToAuthChallenge.ts:183-187`** — add an `"MFA_SETUP"` branch before the
   `UnsupportedError` fallback: validate the session shows a verified software token for the
   user, then complete auth exactly like the other MFA branches
   (`tokenGenerator.generate(..., "Authentication")`, `storeRefreshToken`) and return
   `AuthenticationResult`.

**Admin parity (in scope for "everything").**
5. **`adminInitiateAuth.ts` (`adminUserPasswordAuthFlow`, :26-105)** — add the same MFA gate
   as `initiateAuth`, including `MFA_SETUP` for unenrolled users.
6. **New target `AdminRespondToAuthChallenge`** — `src/targets/adminRespondToAuthChallenge.ts`,
   registered in `targets.ts`. Mirrors `RespondToAuthChallenge` but is keyed by `UserPoolId`
   (admin addressing). Shared challenge-completion logic extracted to a helper (single
   implementation, no versioned dup names) consumed by both targets.

**Token generator.** Reuse `source: "Authentication"` on completion — no new `source` value
needed; the session, not the token, carries partial-auth state (decided in investigation Q6).

**Testing.**
- Unit: new cases in `initiateAuth.test.ts` (MFA_SETUP issued for unenrolled ON-pool user),
  `associateSoftwareToken.test.ts` + `verifySoftwareToken.test.ts` (Session path), a new
  `respondToAuthChallenge.test.ts` MFA_SETUP case, and `adminRespondToAuthChallenge.test.ts`.
- Integration (`integration-tests/aws-sdk/`): full end-to-end forced-enrollment flow with the
  real AWS SDK — `createUserPool(MfaConfiguration:ON)` → `adminCreateUser` →
  `initiateAuth` returns `MFA_SETUP` → `associateSoftwareToken(Session)` →
  `verifySoftwareToken(Session, totp)` → `respondToAuthChallenge(MFA_SETUP, Session)` →
  receives tokens. This is the exact flow boostideal's mandatory-MFA feature will run.

**Error handling.** Expired/mismatched session → `NotAuthorizedError`. `verifySoftwareToken`
bad code → `CodeMismatchError` (unchanged). `RespondToAuthChallenge` MFA_SETUP without a
verified token in the session → `NotAuthorizedError`.

---

## Unit 3 — Sign-out + admin MFA preference (P3)

Three new targets, all with SDK types present (no hand-authoring). Recipe per the target
investigation §"How to add a new target".

- **`GlobalSignOut`** — `Pick<Services,"cognito">`, access-token flow (decode → 
  `getUserPoolForClientId(client_id)` → `getUserByUsername(sub)`), set `RefreshTokens: []`,
  `saveUser`, return `{}`.
- **`AdminUserGlobalSignOut`** — `getUserPool(UserPoolId)` → `getUserByUsername(Username)`,
  set `RefreshTokens: []`, `saveUser`, return `{}`.
- **`AdminSetUserMFAPreference`** — mirror `setUserMFAPreference.ts`, resolving the user by
  `UserPoolId`+`Username` instead of access token. Extract the shared MFA-preference mutation
  into a helper consumed by both (single implementation).

**Known limitation (documented, not a bug):** stateless JWT access tokens cannot be revoked;
global sign-out only invalidates refresh tokens. Matches existing `RevokeToken` behavior.

**Testing.** Per-target unit tests (`vi.fn()` mock services; `signAccessToken` helper for
`GlobalSignOut`) + integration tests: sign out, then assert a subsequent
`REFRESH_TOKEN_AUTH` fails. Router registration test auto-covers the new keys.

---

## Unit 4 — WebAuthn / passkeys (P2)

Largest, greenfield. **Test-oriented** emulation (no real FIDO2 crypto). SDK lacks all
types → hand-author minimal interfaces in the target files. `ChallengeNameType` already
accepts `"WEB_AUTHN"` (it ends in `| string`).

**Data model.** Add to the `User` interface (`src/services/userPoolService.ts`, beside
`SoftwareTokenMfaConfiguration`):
```ts
WebAuthnCredentials?: Array<{
  CredentialId: string;
  FriendlyCredentialName?: string;
  RelyingPartyId?: string;
  CreatedAt: Date;
  // opaque public-key blob stored as-is; not cryptographically verified
  PublicKey?: string;
}>;
```
Persisted transparently via `saveUser` (no new DataStore keys / migrations).

**Targets (hand-authored req/res types).**
- `StartWebAuthnRegistration` (access-token) — returns a `CredentialCreationOptions`-shaped
  blob with a generated challenge stored on a `challengeStore` session.
- `CompleteWebAuthnRegistration` (access-token) — accepts the credential, stores it on the
  user (no attestation verification), returns `{}`.
- `ListWebAuthnCredentials` (access-token) — returns the user's stored credentials.
- `DeleteWebAuthnCredential` (access-token) — removes one by `CredentialId`.

**WEB_AUTHN challenge.** Issue from `initiateAuth`/`adminInitiateAuth` when the user has
WebAuthn credentials and the flow requests it; handle in `respondToAuthChallenge` /
`adminRespondToAuthChallenge` (accept the assertion without signature verification, complete
auth). Uses Unit 1's session store.

**Testing.** Unit tests per target + an integration test covering register → list → login
with `WEB_AUTHN` → delete. Because crypto is stubbed, tests assert flow/shape and storage,
not signature validity. **The stub-not-real-crypto limitation is logged and documented.**

**Risk / open question for Unit 4's own spec:** the exact hand-authored request/response
shapes (align to current AWS Cognito WebAuthn API) and how boostideal's Go SDK v1.59.2
serializes them — verify against a real call capture before finalizing Unit 4.

---

## Cross-cutting conventions

- **Per-unit workflow:** `writing-plans` → implement (TDD where logic is non-trivial per
  `superpowers:test-driven-development`) → `task fmt && task test && task lint` green →
  `verify` the flow end-to-end → GPG-signed commit(s).
- **No tech debt / no dual paths** (CLAUDE.md): migrations replace old code; shared logic is
  extracted once, not duplicated with versioned names.
- **localindex first** for every follow-on investigation.

## Sequencing summary

1. **Unit 0** (image bump) — immediate, unblocks boostideal MFA tests with zero code change.
2. **Unit 1** (challenge/session store) — foundation for Units 2 and 4.
3. **Unit 2** (MFA_SETUP) — the critical parity gap; the mandatory-MFA e2e flow.
4. **Unit 3** (sign-out + admin MFA pref) — quick independent wins.
5. **Unit 4** (WebAuthn) — largest; test-oriented emulation.

Each unit is independently shippable and independently valuable.
</content>
</invoke>
