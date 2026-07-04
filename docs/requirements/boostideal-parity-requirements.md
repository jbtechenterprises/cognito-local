# cognito-local — Feature-Parity Requirements for Boost Ideal

> **Goal:** Everything cognito-local **must support** so that the Boost Ideal backend's
> integration tests exercise the *entire* per-tenant Cognito integration — current
> self-service-signup flows **and** the planned MFA/auth flows — against the emulator
> with **zero "unsupported feature" gaps** (no `t.Skip`, no "verified by real AWS only").
>
> **Repos:** emulator = `jbtechenterprises/cognito-local` (fork of `jagregory/cognito-local`);
> consumer = `solutionsinabox/boostideal` (Go backend).
> **Date:** 2026-07-03. **Fork HEAD:** `v5.3.0-7-ge3086e7`. **Pinned test image:** `cognito-local:5.3.0-m2m` (bumped 2026-07-03 from the stale `5.1.0-m2m-fix`).
>
> Source investigations (in the boostideal repo):
> `docs/investigation/2026-07-03-cognito-local-backend-usage.md` (what we call) and
> `docs/investigation/2026-07-03-cognito-local-support-matrix.md` (what the fork implements).

---

## TL;DR — the one thing to do first

The only gap blocking us **today** is not a missing feature — it's a **stale image**.

- Boostideal's integration tests pin the cognito-local image in three docker-compose files
  (`boostideal/dev/docker/docker-compose.integration_tests.yaml` + two in the `deploy` repo).
  These were bumped from the stale **`cognito-local:5.1.0-m2m-fix`** to **`cognito-local:5.3.0-m2m`** on 2026-07-03.
- `SetUserPoolMfaConfig` was added in **v5.2.0** (PR [#469](https://github.com/jagregory/cognito-local/pull/469), merged 2026-04-18). At v5.1.0 the target isn't registered, so the Router throws `Unsupported x-amz-target header "SetUserPoolMfaConfig"` → HTTP 500.
- **Action (P0):** rebuild/retag the integration-test image from fork HEAD (`v5.3.0`+) — or at minimum ≥ v5.2.0 — and update the three compose files. This immediately unblocks `SetUserPoolMfaConfig` **and** all TOTP MFA targets.

Everything below is the full parity picture, including what's genuinely missing (forced-enrollment `MFA_SETUP` challenge, WebAuthn).

---

## Legend

| Support (fork HEAD) | Meaning |
|---|---|
| ✅ FULL | Implemented and behaves like AWS for our usage |
| 🟡 PARTIAL | Implemented but a behavior we need is missing/divergent |
| ❌ MISSING | No target/handler exists |

| Need | Meaning |
|---|---|
| **NOW** | Called by production/tested code today |
| **MFA** | Needed by the deferred mandatory-MFA + enrollment-UI feature |
| **FUTURE** | Needed for full 100% parity / other planned auth flows |

Upstream refs: PR [#469](https://github.com/jagregory/cognito-local/pull/469) (MERGED, v5.2.0 — TOTP/software-token MFA), PR [#468](https://github.com/jagregory/cognito-local/pull/468) (OPEN — "100% API parity", 122 targets incl. MFA_SETUP + WebAuthn + OAuth2 + SRP), PR [#332](https://github.com/jagregory/cognito-local/pull/332) (OPEN — admin SMS_MFA), Issue [#392](https://github.com/jagregory/cognito-local/issues/392) (OPEN — MFA-challenge Session UUID bug).

---

## A. User-pool lifecycle

| Operation | Need | Fork HEAD | Required behavior | Upstream / action |
|---|---|---|---|---|
| `CreateUserPool` | NOW | ✅ FULL | Must persist & honor: **custom schema attributes** (`custom:tenant_id`, `is_service_user`, …), `MfaConfiguration`, password policy, username/alias/auto-verify attributes. Pools are created per tenant. | OK. Confirm custom-schema round-trips on the bumped image. |
| `DescribeUserPool` | NOW | ✅ FULL | Return the created pool incl. `MfaConfiguration` (so MFA-on can be asserted). | OK |
| `ListUserPools` | NOW | ✅ FULL | Backend does **find-pool-by-name** via `ListUserPools` (`FindUserPoolByName`). Must be paginateable / return all pools so name lookup succeeds. | OK |
| `CreateUserPoolClient` | NOW | ✅ FULL | App client per pool (incl. the `-spa` client + M2M client). | OK |
| `DeleteUserPoolClient` | NOW | ✅ FULL | — | OK |
| `CreateResourceServer` | NOW | ✅ FULL | Non-fatal in our onboarding UoW. | OK |
| `DeleteUserPool` | FUTURE | ✅ FULL | Test cleanup / teardown. | OK |
| `UpdateUserPool` | FUTURE | ✅ FULL | — | OK |

## B. User lifecycle

| Operation | Need | Fork HEAD | Required behavior | Upstream / action |
|---|---|---|---|---|
| `AdminCreateUser` | NOW | ✅ FULL | Create user with **custom attributes** (`custom:tenant_id`, etc.) that persist and return; `SuppressWelcomeEmail`; `email_verified`. | OK |
| `AdminSetUserPassword` | NOW | ✅ FULL | `Permanent: true` sets a usable permanent password (used by signup verify). | OK |
| `AdminEnableUser` / `AdminDisableUser` | NOW | ✅ FULL | — | OK |
| `AdminAddUserToGroup` / `AdminRemoveUserFromGroup` | NOW | ✅ FULL | — | OK |
| `ListUsers` | NOW | ✅ FULL | Backend fetches full pool then filters in-memory; used by the pool-isolation regression test (`ListUsers(victimPool)` asserts attacker absent). Custom attrs must be returned. | OK |
| `ListGroups` | NOW | ✅ FULL | — | OK |
| `AdminGetUser` | MFA | ✅ FULL (v5.2.0+) | Must surface `UserMFASettingList` / `PreferredMfaSetting` (added in #469). | OK on bumped image |

## C. Auth, JWT & tokens

| Capability | Need | Fork HEAD | Required behavior | Upstream / action |
|---|---|---|---|---|
| JWKS per pool | NOW | ✅ FULL | `GET {issuer}/.well-known/jwks.json` + `/.well-known/openid-configuration`; **RS256**; issuer per pool. Backend's JWT verifier fetches JWKS over raw HTTP (not SDK). | OK |
| Token claims | NOW | ✅ FULL | `iss`, `token_use`, `sub`, `aud` (ID token), and **`custom:tenant_id`** on ID-token claims. | OK |
| OAuth2 `client_credentials` (M2M) | NOW | ✅ FULL | `POST /oauth2/token` client-credentials grant for M2M/OAuth2-app auth (the pinned image was built specifically for this — the `-m2m-fix` tag). | OK |
| OAuth2 authorization-code + PKCE | FUTURE | ✅ FULL | Hosted-UI / SPA login (if/when the BFF exercises it against the emulator). | OK |
| `RevokeToken` | FUTURE | ✅ FULL | — | OK |
| `GlobalSignOut` / `AdminUserGlobalSignOut` | FUTURE | ❌ MISSING | Sign-out-everywhere. | In PR #468. |

## D. MFA — pool configuration

| Operation | Need | Fork HEAD | Required behavior | Upstream / action |
|---|---|---|---|---|
| `SetUserPoolMfaConfig` | MFA | ✅ FULL (v5.2.0+) | Turn `MfaConfiguration=ON` with `SoftwareTokenMfaConfiguration.Enabled`. **This is the op that 500s on the pinned v5.1.0 image.** | **P0: bump image.** (PR #469) |
| `GetUserPoolMfaConfig` | MFA | ✅ FULL (v5.2.0+) | Read back pool MFA config to assert it. | OK on bumped image |

## E. MFA — TOTP enrollment & steady-state login (post-login / already-enrolled)

| Operation / behavior | Need | Fork HEAD | Required behavior | Upstream / action |
|---|---|---|---|---|
| `AssociateSoftwareToken` (AccessToken) | MFA | ✅ FULL (v5.2.0+) | Post-login self-service TOTP secret generation. | OK on bumped image |
| `VerifySoftwareToken` (AccessToken) | MFA | ✅ FULL (v5.2.0+) | Verify 6-digit code, mark verified (otplib SHA-1/30s). | OK on bumped image |
| `SetUserMFAPreference` | MFA | ✅ FULL (v5.2.0+) | Toggle `SOFTWARE_TOKEN_MFA` on `UserMFASettingList`. | OK on bumped image |
| `InitiateAuth` → `SOFTWARE_TOKEN_MFA` / `SELECT_MFA_TYPE` | MFA | ✅ FULL (v5.2.0+) | Challenge for **already-enrolled** users at login. | OK on bumped image |
| `RespondToAuthChallenge` → `SOFTWARE_TOKEN_MFA` / `SELECT_MFA_TYPE` | MFA | ✅ FULL (v5.2.0+) | Complete the login MFA challenge. | OK; but see Issue #392 (Session UUID). |
| `AdminSetUserMFAPreference` | MFA | ❌ MISSING | Admin-set MFA preference. | In PR #468. |

## F. MFA — **forced first-login enrollment** (`MFA_SETUP`) — the critical parity gap

This is exactly the flow our mandatory-MFA feature needs: a brand-new self-service user, whose pool has `MfaConfiguration=ON` but who has **not yet enrolled**, must be driven through enrollment on first login.

| Behavior | Need | Fork HEAD | Required behavior (AWS) | Upstream / action |
|---|---|---|---|---|
| `InitiateAuth` / `AdminInitiateAuth` → `ChallengeName=MFA_SETUP` for an **unenrolled** user in an `MfaConfiguration=ON` pool | MFA | ❌ MISSING (🟡 wrong) | AWS returns the `MFA_SETUP` challenge. **cognito-local instead throws `NotAuthorizedError`** (explicit test asserts this). | **P1.** In PR #468. Needs a focused patch or adoption of #468. |
| `RespondToAuthChallenge` → `ChallengeName=MFA_SETUP` case | MFA | ❌ MISSING | Handle the MFA_SETUP response. cognito-local falls through to `UnsupportedError`. | P1. In PR #468. |
| Session-based (in-challenge) `AssociateSoftwareToken` / `VerifySoftwareToken` (called with `Session`, not `AccessToken`) | MFA | ❌ MISSING (🟡 rejected) | During MFA_SETUP the user has no session token yet, so association happens against the challenge `Session`. cognito-local explicitly rejects this ("not supported; call with AccessToken"). | P1. In PR #468. |

**Verdict:** post-login enrollment ✅ works; **forced-first-login `MFA_SETUP` enrollment ❌ does not**. Until this lands, the mandatory-MFA end-to-end flow cannot be integration-tested against cognito-local (matches the deferral already recorded in boostideal `docs/TODO.md`).

## G. WebAuthn / passkeys — entirely absent

| Operation / behavior | Need | Fork HEAD | Required behavior | Upstream / action |
|---|---|---|---|---|
| `StartWebAuthnRegistration` | MFA/FUTURE | ❌ MISSING | Begin passkey registration. | Partly in PR #468 (`completeWebAuthnRegistration` present there; start/list not confirmed). |
| `CompleteWebAuthnRegistration` | MFA/FUTURE | ❌ MISSING | Finish passkey registration. | In PR #468. |
| `ListWebAuthnCredentials` / `DeleteWebAuthnCredential` | MFA/FUTURE | ❌ MISSING | Manage credentials. | Not confirmed in any PR. |
| `InitiateAuth` / `RespondToAuthChallenge` → `WEB_AUTHN` challenge | MFA/FUTURE | ❌ MISSING | Passkey login challenge. | Not confirmed. |

**Verdict:** WebAuthn never existed in any cognito-local version. Passkey MFA (our AWS SDK v1.59.2 supports it) cannot be emulated today. Needed only if/when we ship passkey enrollment (currently deferred; TOTP is the first cut).

## H. Operations the backend does **not** use (documented for completeness)

The Go backend today calls **none** of: `SignUp`, `ConfirmSignUp`, `ForgotPassword`, `ConfirmForgotPassword`, `ChangePassword`, `AdminUpdateUserAttributes`, `AdminDeleteUser`. Self-service signup is implemented **without** Cognito's native `SignUp`/`ConfirmSignUp` (our own email-verification + `AdminCreateUser` + `AdminSetUserPassword`). These are not parity requirements unless a future flow adopts them (all already ✅ in the fork).

---

## Prioritized action plan

1. **P0 — Bump the pinned test image (unblocks MFA pool config + TOTP).**
   Rebuild/retag `cognito-local` from fork HEAD (`v5.3.0`+) and update the three docker-compose files
   (`boostideal/dev/docker/docker-compose.integration_tests.yaml` and the two in `deploy`). This turns
   `SetUserPoolMfaConfig`, `GetUserPoolMfaConfig`, `AssociateSoftwareToken`, `VerifySoftwareToken`,
   `SetUserMFAPreference`, and `AdminGetUser`-MFA-fields from ❌/500 into ✅ with no cognito-local code change.
   Then remove the `SetUserPoolMfaConfig` test-skip/real-AWS-only note in boostideal.

2. **P1 — Forced-enrollment `MFA_SETUP` (Section F).** The single feature blocking end-to-end mandatory-MFA
   integration tests. Either (a) adopt/rebase the relevant slice of PR #468, or (b) carry a focused patch in our
   fork adding: `MFA_SETUP` challenge from `(Admin)InitiateAuth` for unenrolled users in `MfaConfiguration=ON`
   pools, the `MFA_SETUP` case in `RespondToAuthChallenge`, and Session-based `AssociateSoftwareToken`/
   `VerifySoftwareToken`. Also watch Issue #392 (MFA-challenge Session UUID) since our flow relies on the Session.

3. **P2 — WebAuthn/passkeys (Section G).** Only when passkey enrollment is scheduled. Largest gap; source it
   from PR #468 or implement `StartWebAuthnRegistration`/`CompleteWebAuthnRegistration`/`ListWebAuthnCredentials`
   + `WEB_AUTHN` challenge handling.

4. **P3 — Nice-to-haves for broader parity:** `GlobalSignOut`/`AdminUserGlobalSignOut`, `AdminSetUserMFAPreference`
   (both in PR #468).

## Upstream status — are these already raised?

The missing behaviors are **not tracked as standalone issues** on `jagregory/cognito-local`; they live inside PRs:

| Gap | Upstream status |
|---|---|
| `SetUserPoolMfaConfig` + TOTP MFA (Sections D, E) | ✅ **PR #469 MERGED** (v5.2.0). Our blocker is purely the pinned image version. |
| Forced `MFA_SETUP` enrollment (Section F) | 🟡 **PR #468 OPEN** (part of "100% parity"). No standalone issue. |
| WebAuthn (Section G) | 🟡 **PR #468 OPEN** (`completeWebAuthnRegistration`). No standalone issue. |
| `AdminSetUserMFAPreference`, `GlobalSignOut`, SRP, full OAuth2 endpoints | 🟡 **PR #468 OPEN**. |
| admin SMS_MFA / `AdminRespondToAuthChallenge` | 🟡 **PR #332 OPEN** (likely superseded by #468). |
| MFA-challenge Session UUID | 🐛 **Issue #392 OPEN**. |

**Recommendation:** because the WebAuthn / `MFA_SETUP` gaps are bundled inside the large, unmerged PR #468 rather than surfaced as discrete issues, if we want them prioritized independently we should **either (a) file focused upstream issues** (one per: `MFA_SETUP` for unenrolled users; WebAuthn targets) referencing #468, **or (b) maintain the patches in our fork** (which already carries the M2M/OAuth2 work as `5.x-m2m` builds). Given we already run a private fork, carrying a focused `MFA_SETUP` patch on top of a HEAD-bumped image is the lowest-risk path to full parity for the MFA feature.
