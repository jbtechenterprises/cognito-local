# MFA & Auth-Challenge Current State (fork HEAD)

Date: 2026-07-03
Branch: `m2m-oauth2-support`
Scope: map the CURRENT MFA / auth-challenge implementation so we can design a
forced-first-login `MFA_SETUP` enrollment flow with AWS Cognito parity.

All paths relative to repo root `/Users/jon/code/jbtechenterprises/cognito-local`.

---

## Executive summary (the gaps that matter for MFA_SETUP)

1. **There is no challenge/session store.** Every challenge response returns a
   brand-new random `Session: v4()` UUID. `RespondToAuthChallenge` never reads,
   validates, or correlates the `Session` — it only checks it is *present*, then
   re-loads the user from `ChallengeResponses.USERNAME`. So a "session" today
   carries zero state; any state needed for an `MFA_SETUP` round-trip does not
   exist yet.
2. **`MFA_SETUP` challenge is never produced.** `InitiateAuth` with an
   unenrolled user in an `MfaConfiguration=ON` pool throws `NotAuthorizedError`
   instead of returning an `MFA_SETUP` challenge. (Exact site below.)
3. **`AssociateSoftwareToken` / `VerifySoftwareToken` explicitly REJECT the
   `Session` (challenge) path.** They hard-fail with `InvalidParameterError`
   telling the caller to use `AccessToken`. So even if a challenge produced a
   session, the TOTP enrollment targets could not consume it.
4. **`AdminInitiateAuth` has no MFA path at all** and there is **no
   `AdminRespondToAuthChallenge` target** registered — an unsupported target
   error would result.

---

## 1. Auth-challenge flow

### Target registry
`src/targets/targets.ts:52-103` — the `Targets` map. MFA-relevant entries:
`AssociateSoftwareToken`, `AdminInitiateAuth`, `InitiateAuth`,
`RespondToAuthChallenge`, `SetUserMFAPreference`, `SetUserPoolMfaConfig`,
`GetUserPoolMfaConfig`, `VerifySoftwareToken`.
**Not present:** `AdminRespondToAuthChallenge` (no file, not registered).

Router: `src/server/Router.ts:13-21` — unknown `x-amz-target` throws
`UnsupportedError` (`src/errors.ts:1`). So a client calling
`AdminRespondToAuthChallenge` gets an unsupported-target error.

### `InitiateAuth` — `src/targets/initiateAuth.ts`
- Entry `InitiateAuth` at `:334-359`. Dispatches on `AuthFlow`:
  - `USER_PASSWORD_AUTH` → `userPasswordAuthFlow` (`:193-277`)
  - `REFRESH_TOKEN` / `REFRESH_TOKEN_AUTH` → `refreshTokenAuthFlow` (`:279-332`)
  - else → `UnsupportedError` (`:357`)
- `userPasswordAuthFlow` decision order (`:193-277`):
  - status `RESET_REQUIRED` → `PasswordResetRequiredError` (`:233-235`)
  - status `FORCE_CHANGE_PASSWORD` → `newPasswordChallenge` → returns
    `ChallengeName: "NEW_PASSWORD_REQUIRED"` (`:236-238`, builder `:183-191`)
  - wrong password → `InvalidPasswordError` (`:239-241`)
  - status `UNCONFIRMED` → `UserNotConfirmedException` (`:242-244`)
  - **MFA gate (`:246-254`):**
    ```ts
    const userHasMfa =
      (user.MFAOptions ?? []).length > 0 ||
      (user.UserMFASettingList ?? []).length > 0;
    if (
      userPool.options.MfaConfiguration === "ON" ||
      (userPool.options.MfaConfiguration !== "OFF" && userHasMfa)
    ) {
      return verifyMfaChallenge(ctx, user, req, userPool, services);
    }
    ```
  - otherwise `PostAuthentication` trigger then `verifyPasswordChallenge`
    (issues tokens) (`:256-276`).

### ChallengeName values currently PRODUCED
- `"SMS_MFA"` — `initiateAuth.ts:81` (`smsMfaChallenge`, `:36-89`) and
  `respondToAuthChallenge.ts:74` (`sendSmsMfaChallenge`, `:32-82`).
- `"SOFTWARE_TOKEN_MFA"` — `initiateAuth.ts:92` (`softwareTokenMfaChallenge`,
  `:91-103`) and `respondToAuthChallenge.ts:126`.
- `"SELECT_MFA_TYPE"` — `initiateAuth.ts:136` (`verifyMfaChallenge`, `:122-149`,
  returned when >1 method enabled).
- `"NEW_PASSWORD_REQUIRED"` — `initiateAuth.ts:184` (`newPasswordChallenge`).
- **`"MFA_SETUP"` is never produced anywhere.**

### `verifyMfaChallenge` — the NotAuthorized-instead-of-MFA_SETUP site
`src/targets/initiateAuth.ts:122-149`:
```ts
const verifyMfaChallenge = async (...) => {
  const methods = enabledMfaMethods(user);
  if (methods.length === 0) {
    throw new NotAuthorizedError();          // <-- :130-132  SHOULD be MFA_SETUP
  }
  if (methods.length > 1) {
    return { ChallengeName: "SELECT_MFA_TYPE", ... Session: v4() };  // :134-143
  }
  if (methods[0] === "SOFTWARE_TOKEN_MFA") return softwareTokenMfaChallenge(user);
  return smsMfaChallenge(ctx, user, req, userPool, services);
};
```
`enabledMfaMethods` (`:105-120`) derives methods from `user.UserMFASettingList`
(falling back to legacy `MFAOptions` SMS). For a pool with `MfaConfiguration=ON`
and an unenrolled user, `methods.length === 0`, so **`NotAuthorizedError()`**
(`src/errors.ts:12-16`, message "User not authorized", code
`NotAuthorizedException`) is thrown at `initiateAuth.ts:131`. In real Cognito
this case returns `ChallengeName: "MFA_SETUP"` with a session.

### ChallengeName values currently HANDLED (`RespondToAuthChallenge`)
`src/targets/respondToAuthChallenge.ts:84-213`:
- Preconditions (`:89-99`): requires `ChallengeResponses`,
  `ChallengeResponses.USERNAME`, and `Session` — else `InvalidParameterError`.
  Note `Session` is only checked for presence at `:97-99`; its value is never
  validated.
- Loads user via `getUserByUsername(ChallengeResponses.USERNAME)` (`:104-107`);
  missing user/client → `NotAuthorizedError` (`:108-110`).
- Handled `ChallengeName`s:
  - `"SELECT_MFA_TYPE"` (`:112-142`): reads `ChallengeResponses.ANSWER`; branches
    to SMS or emits a fresh `SOFTWARE_TOKEN_MFA` challenge with new `Session:
    v4()`.
  - `"SMS_MFA"` (`:144-153`): compares `user.MFACode` to
    `ChallengeResponses.SMS_MFA_CODE`; mismatch → `CodeMismatchError`.
  - `"SOFTWARE_TOKEN_MFA"` (`:154-168`): verifies TOTP against
    `user.SoftwareTokenMfaConfiguration.Secret` (must be `Verified: true`); uses
    `verify` from `src/services/totp.ts`; failure → `CodeMismatchError`.
  - `"NEW_PASSWORD_REQUIRED"` (`:169-182`): sets new password, status →
    `CONFIRMED`.
  - else → `UnsupportedError` (`:183-187`). **`"MFA_SETUP"` falls here — not
    handled.**
- On success: optional `PostAuthentication` trigger, then
  `tokenGenerator.generate(..., "Authentication")` returns
  `AuthenticationResult` (`:189-212`).

### `AdminInitiateAuth` — `src/targets/adminInitiateAuth.ts`
- Entry `:161-174`: `ADMIN_USER_PASSWORD_AUTH` → `adminUserPasswordAuthFlow`;
  refresh flows → `refreshTokenAuthFlow`; else `UnsupportedError`.
- `adminUserPasswordAuthFlow` (`:26-105`): validates password, rejects
  `UNCONFIRMED`, then **immediately issues tokens** — there is **no MFA gate,
  no challenge branch**. It cannot emit `SMS_MFA`, `SOFTWARE_TOKEN_MFA`,
  `SELECT_MFA_TYPE`, or `MFA_SETUP`.

### Session creation / storage / validation
- Created ad-hoc as `v4()` (uuid) at each challenge return:
  `initiateAuth.ts:87, 102, 141, 190`; `respondToAuthChallenge.ts:80, 136`.
- **No session store / challenge store exists.** The only stateful stores are:
  - `src/oauth2/authorizationCodeStore.ts` (`AuthorizationCodeStore`, in-memory
    `Map`, TTL) — used purely for the OAuth2 authorization-code flow, unrelated
    to challenge sessions.
  - User state persisted via `UserPoolServiceImpl.saveUser`
    (`src/services/userPoolService.ts:402-406`) into the StormDB JSON datastore.
- Session is **never validated**. `RespondToAuthChallenge` requires the field to
  be present (`respondToAuthChallenge.ts:97-99`) but ignores its value; user
  correlation is done entirely via `ChallengeResponses.USERNAME`. Cross-request
  state that AWS carries in the session (e.g. which challenge is in flight, the
  in-progress software-token secret for `MFA_SETUP`) has **no home today**.

---

## 2. TOTP / software-token MFA targets and their Session rejections

### `AssociateSoftwareToken` — `src/targets/associateSoftwareToken.ts:19-60`
```ts
if (!req.AccessToken && !req.Session) {
  throw new InvalidParameterError("Either AccessToken or Session is required"); // :22-26
}
if (!req.AccessToken) {
  throw new InvalidParameterError(
    "AssociateSoftwareToken via Session (MFA_SETUP flow) is not supported; call with AccessToken",
  );                                                                            // :28-32  <-- REJECTION
}
```
Then it decodes the access token (`jwt.decode` → `Token`), loads the user by
`decoded.sub`, generates a secret via `generateSecret()`
(`src/services/totp.ts:14`), and saves
`SoftwareTokenMfaConfiguration: { Secret, Verified: false }` (`:48-55`),
returning `{ SecretCode }`.

### `VerifySoftwareToken` — `src/targets/verifySoftwareToken.ts:23-86`
```ts
if (!req.UserCode) throw new InvalidParameterError("Missing required parameter UserCode"); // :26-28
if (!req.AccessToken && !req.Session) {
  throw new InvalidParameterError("Either AccessToken or Session is required"); // :29-33
}
if (!req.AccessToken) {
  throw new InvalidParameterError(
    "VerifySoftwareToken via Session (MFA_SETUP flow) is not supported; call with AccessToken",
  );                                                                            // :34-38  <-- REJECTION
}
```
On valid `AccessToken`: decode → load user by `decoded.sub`; require an
associated secret (`:54-59`, else `InvalidParameterError "User has not
associated a software token"`); `verify(secret, UserCode)` else
`CodeMismatchError` (`:61-63`); then persists
`SoftwareTokenMfaConfiguration: { Secret, Verified: true, FriendlyDeviceName }`
and appends `"SOFTWARE_TOKEN_MFA"` to `UserMFASettingList` (`:65-80`). Returns
`{ Status: "SUCCESS", Session: req.Session }` (`:82-85`) — it echoes back
whatever `Session` was passed but does nothing with it.

### `SetUserMFAPreference` — `src/targets/setUserMFAPreference.ts:18-77`
- Requires `AccessToken` only (no Session branch at all):
  `if (!req.AccessToken) throw new InvalidParameterError("Missing required
  parameter AccessToken");` (`:21-23`).
- Decodes token, loads user, then:
  - If enabling software MFA but token not verified →
    `InvalidParameterError "User has not verified software token MFA"`
    (`:42-46`).
  - Builds `UserMFASettingList` set from `SMSMfaSettings` /
    `SoftwareTokenMfaSettings` (`:48-56`).
  - Computes `PreferredMfaSetting` (`:58-63`); preferred-but-not-enabled →
    `InvalidParameterError` (`:64-68`).
  - Persists `UserMFASettingList` + `PreferredMfaSetting` (`:70-74`).

**Summary of rejection sites (exact strings):**
| Target | Session rejection string | Line |
|---|---|---|
| AssociateSoftwareToken | `"AssociateSoftwareToken via Session (MFA_SETUP flow) is not supported; call with AccessToken"` | associateSoftwareToken.ts:29-31 |
| VerifySoftwareToken | `"VerifySoftwareToken via Session (MFA_SETUP flow) is not supported; call with AccessToken"` | verifySoftwareToken.ts:35-37 |
| InitiateAuth (unenrolled, MfaConfiguration=ON) | `NotAuthorizedError()` → `NotAuthorizedException` / "User not authorized" | initiateAuth.ts:131 |

All three are the friction points a forced `MFA_SETUP` flow must replace with
proper challenge/session handling.

---

## 3. MFA config storage

### Pool-level config
- `SetUserPoolMfaConfig` — `src/targets/setUserPoolMfaConfig.ts:15-59`. Writes to
  the user pool options via `userPool.updateOptions`:
  - `MfaConfiguration` (`"OFF" | "ON" | "OPTIONAL"`), `SmsAuthenticationMessage`,
    `SmsConfiguration`, and `SoftwareTokenMfaConfiguration: { Enabled }`
    (`:23-39`).
- `GetUserPoolMfaConfig` — `src/targets/getUserPoolMfaConfig.ts:15-31`. Reads
  those same fields back.
- Storage type: `UserPool = UserPoolType & { Id; SoftwareTokenMfaConfiguration?:
  { Enabled: boolean } }` at `src/services/userPoolService.ts:165-170`.
  `MfaConfiguration` comes from the AWS SDK `UserPoolType`. Persisted as the
  per-pool JSON file in the data directory (one `.json` per pool; see
  `CognitoServiceImpl.init` `src/services/cognitoService.ts:425-451`).

### Per-user MFA settings
`User` interface — `src/services/userPoolService.ts:96-130`:
- `MFAOptions?: MFAOptionListType` (`:99`) — legacy SMS options.
- `PreferredMfaSetting?: StringType` (`:100`).
- `UserMFASettingList?: UserMFASettingListType` (`:103`).
- `MFACode?: string` (`:111`) — transient SMS OTP.
- **Software-token secret persistence (`:121-129`):**
  ```ts
  SoftwareTokenMfaConfiguration?: {
    Secret: string;
    Verified: boolean;
    FriendlyDeviceName?: string;
  };
  ```
  Comment notes it is "Internal only — never returned by GetUser /
  AdminGetUser responses."
- Persisted via `saveUser` → `dataStore.set(["Users", user.Username], user)`
  (`src/services/userPoolService.ts:402-406`), backed by StormDB
  (`src/services/dataStore/stormDb.ts`).

---

## 4. Token generator involvement in challenge completion

- Interface `TokenGenerator` — `src/services/tokenGenerator.ts:99-117`:
  `generate(ctx, user, userGroups, userPoolClient, clientMetadata, source)` and
  `generateWithClientCreds(ctx, userPoolClient)`.
- `source` union: `"AuthenticateDevice" | "Authentication" | "HostedAuth" |
  "NewPasswordChallenge" | "RefreshTokens"` (`:106-112`).
- Implementation `JwtTokenGenerator.generate` — `src/services/tokenGenerator.ts:153-267`:
  builds RS256 access/id/refresh JWTs, runs `PreTokenGeneration` trigger if
  enabled, signs with `PrivateKey.pem`. Access token hardcodes
  `scope: "aws.cognito.signin.user.admin"` (`:186`, marked TODO).
- Called at challenge completion:
  - `RespondToAuthChallenge` success — `respondToAuthChallenge.ts:204-211`
    (`source: "Authentication"`), returns tokens as `AuthenticationResult`.
  - `InitiateAuth` password success — `initiateAuth.ts:161-172`
    (`verifyPasswordChallenge`), then `storeRefreshToken` (`:174`).
  - `InitiateAuth` refresh — `initiateAuth.ts:306-317`.
  - `AdminInitiateAuth` — `adminInitiateAuth.ts:81-88` and `:137-144`.
- Note: the token generated after a `SOFTWARE_TOKEN_MFA` / `SMS_MFA` challenge
  uses `source: "Authentication"`, not a challenge-specific source. There is no
  `"MFA_SETUP"` source and no separate token type for a "session-only" partial
  auth — a forced-setup flow that must issue a session (not tokens) has no
  existing mechanism.

---

## 5. Existing tests & conventions

### Unit tests (per target, `src/targets/*.test.ts`) — vitest
Convention (see `src/targets/respondToAuthChallenge.test.ts:1-64`):
- Build mocks from `src/__tests__/`: `newMockCognitoService`,
  `newMockUserPoolService`, `newMockTokenGenerator`, `newMockTriggers`,
  `newMockMessages`, `ClockFake`, `TestContext`, and `testDataBuilder` (`TDB`).
- Construct the target by calling its factory with the mocked `Services` subset,
  e.g. `RespondToAuthChallenge({ clock, cognito, messages, otp, tokenGenerator,
  triggers })`.
- Invoke as `target(TestContext, req)` and assert with
  `.rejects.toBeInstanceOf(NotAuthorizedError)` / `.rejects.toEqual(new
  InvalidParameterError(...))` etc.
- Relevant unit test files: `initiateAuth.test.ts`,
  `respondToAuthChallenge.test.ts`, `adminInitiateAuth.test.ts`,
  `associateSoftwareToken.test.ts`, `verifySoftwareToken.test.ts`,
  `setUserMFAPreference.test.ts`, `getUserPoolMfaConfig.test.ts` (+
  `setUserPoolMfaConfig` covered via others). TOTP helpers imported from
  `src/services/totp` (`generateSecret`, `generate as genTotp`) in
  `respondToAuthChallenge.test.ts:25`.

### Integration tests (`integration-tests/aws-sdk/*.test.ts`) — real HTTP + real AWS SDK
- Harness `withCognitoSdk` — `integration-tests/aws-sdk/setup.ts:29-137`. Spins
  a real `createServer` on port 0 with StormDB in a temp dir, real
  `JwtTokenGenerator`, real `MessagesService` + `FakeMessageDeliveryService`,
  triggers disabled (`enabled: () => false`). Tests get a real
  `AWS.CognitoIdentityServiceProvider` pointed at the local endpoint.
- Pattern (see `integration-tests/aws-sdk/associateSoftwareToken.test.ts`):
  `createUserPool` → `createUserPoolClient` → `adminCreateUser` →
  `adminSetUserPassword` → `initiateAuth(USER_PASSWORD_AUTH)` → use
  `auth.AuthenticationResult.AccessToken`. Assertions via
  `.rejects.toMatchObject({ code: "InvalidParameterException" })` etc.
- MFA-relevant integration files: `adminInitiateAuth.test.ts`,
  `initiateAuth.test.ts`, `respondToAuthChallenge.test.ts`,
  `associateSoftwareToken.test.ts`, `verifySoftwareToken.test.ts`,
  `setUserMFAPreference.test.ts`, `getUserPoolMfaConfig.test.ts`.

---

## Open questions / design implications for forced `MFA_SETUP`

1. **Session store is a prerequisite.** To implement `MFA_SETUP` parity we need
   a real challenge-session store (analogous to `AuthorizationCodeStore`) that
   correlates a `Session` value across `InitiateAuth → AssociateSoftwareToken →
   VerifySoftwareToken → RespondToAuthChallenge`, and carries the in-progress
   secret + which user + which challenge. Currently `Session` is opaque and
   ignored.
2. **`initiateAuth.ts:131`** must change from `throw new NotAuthorizedError()` to
   returning `ChallengeName: "MFA_SETUP"` (with `ChallengeParameters` incl.
   `MFAS_CAN_SETUP`, and a stored `Session`) when the pool is `ON`/`OPTIONAL`
   and the user has no enrolled methods (forced when `ON`).
3. **`AssociateSoftwareToken` / `VerifySoftwareToken`** must gain a Session path
   (currently hard-rejected at associateSoftwareToken.ts:29-31 /
   verifySoftwareToken.ts:35-37) that resolves the user + secret from the
   challenge session instead of an `AccessToken`.
4. **`RespondToAuthChallenge`** needs an `"MFA_SETUP"` branch (currently falls to
   `UnsupportedError` at :183-187) to finalize enrollment and issue tokens.
5. **`AdminInitiateAuth` has no MFA/challenge handling** and
   **`AdminRespondToAuthChallenge` does not exist** — parity for admin flows is
   a separate, larger gap (decide whether in scope).
6. **Token generator** has no `MFA_SETUP` source and no notion of a
   session-only partial authentication; decide whether that needs a new `source`
   value or just reuse `"Authentication"` on completion.
7. Decide session TTL / storage location (in-memory Map like
   `AuthorizationCodeStore`, or persisted) and whether Session must survive
   process restarts for local-dev ergonomics.
