# Target registration & services — investigation

Date: 2026-07-03
Branch: m2m-oauth2-support
Goal: understand extension mechanics so we can add new Cognito API targets
(`GlobalSignOut`, `AdminUserGlobalSignOut`, `AdminSetUserMFAPreference`, and the
WebAuthn family: `StartWebAuthnRegistration`, `CompleteWebAuthnRegistration`,
`ListWebAuthnCredentials`, `DeleteWebAuthnCredential`) plus a `WEB_AUTHN`
challenge.

All paths absolute-from-repo-root under `/Users/jon/code/jbtechenterprises/cognito-local`.

---

## 1. The Router — how `x-amz-target` maps to a handler

### The registry (the map)
`src/targets/targets.ts` — a single `const Targets = { ... } as const` object
(lines 52–103). Keys are the Cognito API operation names (the *action* part of
the `x-amz-target` header). Values are the target **factory** functions imported
at the top of the file (lines 1–50). This object is the authoritative registry —
there is no switch statement.

```ts
// src/targets/targets.ts:52
export const Targets = {
  AddCustomAttributes,
  AssociateSoftwareToken,
  ...
  RevokeToken,
  SetUserMFAPreference,
  ...
  VerifyUserAttribute,
} as const;
```

### The type layer
`src/targets/Target.ts`:
```ts
// src/targets/Target.ts:4
export type TargetName = keyof typeof Targets;

// :6
export type Target<Req extends {}, Res extends {}> = (
  ctx: Context,
  req: Req,
) => Promise<Res>;

// :11 — the runtime guard used by the router
export const isSupportedTarget = (name: string): name is TargetName =>
  Object.keys(Targets).includes(name);
```

### Where the header is parsed (HTTP layer)
`src/server/server.ts` extracts and validates the `x-amz-target` header before
the router runs. The integration tests pin the exact behaviour
(`integration-tests/server.test.ts`):
- missing header → HTTP 400 `{ message: "Missing x-amz-target header" }`
- malformed header (no `.`) → HTTP 400 `{ message: "Invalid x-amz-target header" }`
- The header format is `Prefix.Action` (e.g.
  `AWSCognitoIdentityProviderService.RevokeToken`); the server splits on `.` and
  passes only the **action** (`RevokeToken`) to the router.

### Where the unsupported error is thrown
`src/server/Router.ts:11-19`:
```ts
export const Router =
  (services: Services): Router =>
  (target: string) => {
    if (!isSupportedTarget(target)) {
      return () =>
        Promise.reject(
          new UnsupportedError(`Unsupported x-amz-target header "${target}"`),
        );
    }
    const t = Targets[target](services);   // :21 — factory called with full Services
    return async (ctx, req) => { ... t(...) ... };  // :23 — per-request invocation
  };
```
`UnsupportedError` is defined in `src/errors.ts:1` (`class UnsupportedError extends Error {}`).
The HTTP layer maps an `UnsupportedError` bubbling out of a route to HTTP **500**
with body `{ __type: "CognitoLocal#Unsupported", message: "Cognito Local unsupported feature: ..." }`
(see `integration-tests/server.test.ts` "converts UnsupportedErrors ... to a 500 error").

Note the two-phase call: `Targets[target](services)` (line 21) runs the
**factory** at route-resolution time to bind services; the returned `Target`
`(ctx, req) => Promise` runs per request (line 23–37), wrapping with a child
logger scoped to the target name.

### Router test contract
`src/server/Router.test.ts:18` iterates `Object.keys(Targets)` with `it.each`
and asserts every registered target resolves to a defined route. **Adding a key
to `Targets` automatically extends this test** — no test edit required for the
"is registered" check.

### To register a new target (mechanical steps)
1. Create `src/targets/<camelCaseName>.ts` exporting a factory `export const <PascalName> = (...) => Target<...>`.
2. In `src/targets/targets.ts`: add an `import { <PascalName> } from "./<camelCaseName>";`
   (imports are kept alphabetical) and add `<PascalName>,` to the `Targets` object.
3. That's it for routing — `TargetName`, `isSupportedTarget`, and the Router test
   all derive from the `Targets` object automatically.

---

## 2. Anatomy of a typical target handler

Canonical simple example — `src/targets/adminSetUserPassword.ts` (whole file):
```ts
import type {
  AdminSetUserPasswordRequest,
  AdminSetUserPasswordResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import type { Target } from "./Target";

export type AdminSetUserPasswordTarget = Target<
  AdminSetUserPasswordRequest,
  AdminSetUserPasswordResponse
>;

type AdminSetUserPasswordServices = Pick<Services, "clock" | "cognito">;

export const AdminSetUserPassword =
  ({ cognito, clock }: AdminSetUserPasswordServices): AdminSetUserPasswordTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) throw new UserNotFoundError("User does not exist");
    await userPool.saveUser(ctx, { ...user, Password: req.Password, ... });
    return {};
  };
```

Conventions every target follows:
- **Request/Response types** are imported from
  `aws-sdk/clients/cognitoidentityserviceprovider` (the bundled AWS SDK v2 model —
  see §7 for codegen note). There is **no local codegen** — types come straight
  from the SDK `.d.ts`.
- **Exported factory** named in PascalCase matching the `Targets` key.
- **Exported `<Name>Target` type alias** = `Target<Req, Res>`; imported by the
  target's own test.
- **A local `<Name>Services` type** = `Pick<Services, ...>` naming *only* the
  services this target needs. The factory destructures them. This is the
  dependency-injection convention. (Some very old targets take the whole
  `Services`, e.g. `respondToAuthChallenge` uses a `Pick` with 6 members.)
- **Curried shape**: `(services) => async (ctx, req) => res`. The outer call
  happens once in the Router (line 21); the inner runs per request.
- **`ctx`** is `Context` (`src/services/context.ts`) — carries `logger`.
- Errors are thrown as `CognitoError` subclasses from `src/errors.ts`.

### The barrel / registry
There is **no `index.ts` barrel** for targets. The single aggregation point is
`src/targets/targets.ts` (the `Targets` object). `src/targets/Target.ts` derives
`TargetName` from it.

### Access-token-authenticated targets
Targets that operate on "the current user" (no `UserPoolId`/`Username` in the
request) decode the access token to find the user. Pattern from
`src/targets/setUserMFAPreference.ts:21-37`:
```ts
if (!req.AccessToken) throw new InvalidParameterError("Missing required parameter AccessToken");
const decoded = jwt.decode(req.AccessToken) as Token | null;
if (!decoded) throw new InvalidParameterError();
const userPool = await cognito.getUserPoolForClientId(ctx, decoded.client_id);
const user = await userPool.getUserByUsername(ctx, decoded.sub);
if (!user) throw new NotAuthorizedError();
```
`Token` type is imported from `src/services/tokenGenerator.ts`. `jwt` is
`jsonwebtoken`. This is the pattern `GlobalSignOut` (access-token only) and the
WebAuthn registration targets (access-token only) must follow.

There are helper assertion utilities in `src/targets/utils/assertions.ts`
(`assertRequiredParameter`, `assertParameterLength`).

---

## 3. The `services` container (`Services`)

Definition — `src/services/index.ts:15-23`:
```ts
export interface Services {
  clock: Clock;
  cognito: CognitoService;
  config: Config;
  messages: Messages;
  otp: () => string;
  tokenGenerator: TokenGenerator;
  triggers: Triggers;
}
```

Wired together in **`src/server/defaults.ts:21-75`** (`createDefaultServer`):
- `clock = new DateClock()` (`src/services/clock.ts`)
- `dataStoreFactory = new StormDBDataStoreFactory(dataDirectory)`
  (`src/services/dataStore/stormDb.ts`) — file-backed JSON store under
  `.cognito/db`.
- `cognitoServiceFactory = new CognitoServiceFactoryImpl(dataDirectory, dataStoreFactory, new UserPoolServiceFactoryImpl(clock, dataStoreFactory))`
  → `cognitoClient = await cognitoServiceFactory.create(ctx, config.UserPoolDefaults)`.
- `triggers = new TriggersService(clock, cognitoClient, new LambdaService(...), new CryptoService(...))`.
- `messages = new MessagesService(triggers, new MessageDeliveryService(new ConsoleMessageSender()))`.
- `otp` imported from `src/services/otp.ts`.
- `tokenGenerator = new JwtTokenGenerator(clock, triggers, config.TokenConfig)`
  (`src/services/tokenGenerator.ts`).
- Final: `createServer(Router(services), logger, config.ServerConfig, services)`.

### How a target reaches the data store / user pool
`services.cognito` is a `CognitoService` (`src/services/cognitoService.ts:263-277`):
```ts
export interface CognitoService {
  createUserPool(ctx, userPool): Promise<UserPool>;
  deleteUserPool(ctx, userPool): Promise<void>;
  getAppClient(ctx, clientId): Promise<AppClient | null>;
  getUserPool(ctx, userPoolId): Promise<UserPoolService>;
  getUserPoolForClientId(ctx, clientId): Promise<UserPoolService>;
  listAppClients(ctx, userPoolId): Promise<readonly AppClient[]>;
  listUserPools(ctx): Promise<readonly UserPool[]>;
}
```
So a target's path to data is: `cognito.getUserPool(ctx, UserPoolId)` (admin
targets, keyed by pool id) **or** `cognito.getUserPoolForClientId(ctx, clientId)`
(user/client targets) → returns a `UserPoolService` → call its user/group/token
methods. The `UserPoolService` owns the per-pool `DataStore`.

`UserPoolService` interface — `src/services/userPoolService.ts:172-201`. Relevant
methods for the new work:
- `getUserByUsername(ctx, username)` / `getUserByRefreshToken(ctx, refreshToken)`
- `listUsers(ctx, filter?)`
- `saveUser(ctx, user)` — persists to `["Users", user.Username]`
- `storeRefreshToken(ctx, refreshToken, user)` — appends to `user.RefreshTokens`
- `updateOptions(ctx, userPool)` — persists pool-level config (used by
  `AddCustomAttributes` / MFA config)

---

## 4. Token / session state (for GlobalSignOut design)

**There is no separate session/token store.** Refresh tokens are stored **inside
the User record** as `User.RefreshTokens: string[]`
(`src/services/userPoolService.ts:112`). Access/ID tokens are stateless JWTs
(signed by `JwtTokenGenerator`, `src/services/tokenGenerator.ts`) and are **not**
tracked server-side.

Producers of refresh tokens:
- `src/targets/initiateAuth.ts:174` — `await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user)`
- `src/targets/adminInitiateAuth.ts:90` — same
- New users start with `RefreshTokens: []` (`adminCreateUser.ts:151`, `signUp.ts:144`)

Refresh-token → user lookup:
- `initiateAuth.ts:296` and `adminInitiateAuth.ts:127` call
  `userPool.getUserByRefreshToken(...)` for the `REFRESH_TOKEN_AUTH` flow.
- Implementation `src/services/userPoolService.ts:333-346`: `listUsers` then
  `find` whose `RefreshTokens` includes the token.

### How `RevokeToken` works today
`src/targets/revokeToken.ts` (whole file, 42 lines):
1. `cognito.getUserPoolForClientId(ctx, req.ClientId)`
2. `listUsers(ctx)`, find the user whose `RefreshTokens` includes `req.Token`
3. If none → `NotAuthorizedError`
4. Splice the one token out and `saveUser` with the trimmed `RefreshTokens`.

It revokes **one** refresh token.

### Where "global sign out" invalidation lives (design)
`GlobalSignOut` / `AdminUserGlobalSignOut` should **clear the entire
`RefreshTokens` array** for a user (set to `[]`) and `saveUser`. That is the only
server-side session state that exists.
- `GlobalSignOut` request = `{ AccessToken }` only
  (`aws-sdk .d.ts:2697`, `GlobalSignOutRequest.AccessToken: TokenModelType`).
  Resolve user via the access-token pattern (§2): decode → `getUserPoolForClientId(decoded.client_id)`
  → `getUserByUsername(decoded.sub)`.
- `AdminUserGlobalSignOut` request = `{ UserPoolId, Username }`
  (`aws-sdk .d.ts:1459`). Resolve via `cognito.getUserPool(UserPoolId)` →
  `getUserByUsername(Username)`.
- Both then `saveUser(ctx, { ...user, RefreshTokens: [] })` and return `{}`.
- Caveat: because access tokens are stateless JWTs, cognito-local cannot truly
  invalidate an already-issued access token — global sign out only prevents
  refresh. This matches the existing `RevokeToken` limitation and is acceptable
  for a local emulator. Document it.

---

## 5. Data model (User & UserPool records)

### User — `src/services/userPoolService.ts:96-130`
```ts
export interface User {
  Attributes: AttributeListType;      // includes "sub", "email", "custom:*"
  Enabled: boolean;
  MFAOptions?: MFAOptionListType;     // SMS MFA options
  PreferredMfaSetting?: StringType;
  UserCreateDate: Date;
  UserLastModifiedDate: Date;
  UserMFASettingList?: UserMFASettingListType;  // e.g. ["SMS_MFA","SOFTWARE_TOKEN_MFA"]
  Username: string;
  UserStatus: UserStatusType;

  // extra attributes for Cognito Local (not in AWS SDK type):
  Password: string;
  AttributeVerificationCode?: string;
  ConfirmationCode?: string;
  MFACode?: string;
  RefreshTokens: string[];
  UnverifiedAttributeChanges?: AttributeListType;
  SoftwareTokenMfaConfiguration?: { Secret: string; Verified: boolean; FriendlyDeviceName?: string };
}
```
Key point: **the `User` interface is a hand-authored superset of the SDK type**,
with Cognito-Local-only fields appended (`Password`, `RefreshTokens`,
`SoftwareTokenMfaConfiguration`, etc.). **This is exactly where WebAuthn
credentials should be stored** — add e.g. `WebAuthnCredentials?: WebAuthnCredential[]`
to this interface, following the `SoftwareTokenMfaConfiguration` precedent.

- **Custom attributes** live in `User.Attributes` with names prefixed `custom:`
  (helper `customAttributes()` at `userPoolService.ts:91`). The *schema* for
  custom attributes lives on the pool (`UserPool.SchemaAttributes`, managed by
  `AddCustomAttributes`).
- **MFA fields**: `UserMFASettingList`, `PreferredMfaSetting`, `MFAOptions`
  (SMS), `SoftwareTokenMfaConfiguration` (TOTP). `SetUserMFAPreference`
  (`src/targets/setUserMFAPreference.ts`) already mutates these — the new
  `AdminSetUserMFAPreference` should mirror it but resolve the user by
  `UserPoolId`+`Username` instead of by access token.

### UserPool — `src/services/userPoolService.ts:165-170`
```ts
export type UserPool = UserPoolType & {   // UserPoolType from aws-sdk
  Id: string;
  SoftwareTokenMfaConfiguration?: { Enabled: boolean };
};
```

### Persistence (DataStore)
- Interface `src/services/dataStore/dataStore.ts`: `get/set/delete/getRoot` on a
  `string | string[]` key path.
- Impl: `StormDBDataStoreFactory` (`src/services/dataStore/stormDb.ts`) — JSON
  files under the data directory (one file per pool id, plus a clients file).
- Users are stored at key path `["Users", username]`
  (`userPoolService.ts:405`, `saveUser`). `listUsers` reads the `"Users"` map
  (`:384`). Pool options at `"Options"` (`:398`). Groups at `["Groups", name]`.

So storing WebAuthn credentials on the `User` and calling `saveUser` persists
them transparently — no new DataStore keys or migrations required.

---

## 6. Test harness conventions for targets

Reference: `src/targets/setUserMFAPreference.test.ts` and
`src/targets/adminAddUserToGroup.test.ts`.

- **Runner**: `vitest` (`import { beforeEach, describe, expect, it, type MockedObject } from "vitest"`).
- **Mocks (real objects, `vi.fn()`-backed — not `testify`-style mocks)**:
  - `src/__tests__/mockCognitoService.ts` → `newMockCognitoService(userPoolService?)`.
    Its `getUserPool` and `getUserPoolForClientId` both resolve to the passed
    `UserPoolService` mock.
  - `src/__tests__/mockUserPoolService.ts` → `newMockUserPoolService(config?)`.
    Returns a `MockedObject<UserPoolService>` with every method as `vi.fn()`.
  - `src/__tests__/testContext.ts` → `TestContext` (a `Context` with a logger).
  - `src/__tests__/testDataBuilder.ts` (imported as `* as TDB`) → factory builders
    `TDB.user(partial?)`, `TDB.userPool(partial?)`, `TDB.group(partial?)`,
    `TDB.appClient(partial?)`. `TDB.user()` defaults `RefreshTokens: []`,
    `UserStatus: "CONFIRMED"`, and sets `Attributes` incl. a `sub`.
- **Clock**: `ClockFake` (from `src/__tests__/`), `new ClockFake(originalDate)`,
  `clock.advanceTo(date)`.
- **Typical setup**:
  ```ts
  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    myTarget = MyTarget({ cognito: newMockCognitoService(mockUserPoolService) });
  });
  ```
- **Access-token targets** sign a real JWT with `jsonwebtoken` +
  `src/keys/cognitoLocal.private.json` (see `setUserMFAPreference.test.ts:16-35`
  for the exact `signAccessToken` helper — copy it for GlobalSignOut / WebAuthn
  registration tests). The `sub`/`client_id`/`username` claims must be set
  because targets read them via `jwt.decode`.
- **Assertions**: `expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, expect.objectContaining({ ... }))`.
- **CLAUDE.md rule**: the *global* CLAUDE.md forbids mocks in favour of
  integration tests, but **this repo's actual convention for target unit tests is
  the `vi.fn()` mock services above** — every existing target test uses them.
  There is also a separate `integration-tests/` dir (e.g. `server.test.ts`) using
  `supertest` against a real `createServer`. Match the surrounding files: add a
  `src/targets/<name>.test.ts` using the mock-service pattern, and optionally an
  integration test.

---

## 7. Codegen / AWS SDK model — CRITICAL for WebAuthn

- **No local codegen exists.** Request/Response types are imported directly from
  `aws-sdk/clients/cognitoidentityserviceprovider` (`.d.ts`). The bundled version
  is **aws-sdk v2.1145.0** (June 2022 era), file:
  `node_modules/aws-sdk/clients/cognitoidentityserviceprovider.d.ts`.
- Availability of the requested operations' types in that SDK version:
  - `GlobalSignOutRequest` / `GlobalSignOutResponse` — **present** (`.d.ts:2697`).
  - `AdminUserGlobalSignOutRequest` / `...Response` — **present** (`.d.ts:1459`).
  - `AdminSetUserMFAPreferenceRequest` / `...Response` — **present**.
  - **WebAuthn types — ABSENT.** `grep` for `StartWebAuthnRegistration`,
    `CompleteWebAuthnRegistration`, `ListWebAuthnCredentials`,
    `DeleteWebAuthnCredential`, and even the string `WEB_AUTHN` returns **zero
    hits** in the SDK v2.1145.0 model. WebAuthn was added to Cognito in late 2024,
    long after this SDK build.
- `ChallengeNameType` (`.d.ts:1610`) is
  `"SMS_MFA"|"SOFTWARE_TOKEN_MFA"|...|"NEW_PASSWORD_REQUIRED"|string`. It ends
  with `|string`, so a `"WEB_AUTHN"` challenge value **is assignable** without SDK
  changes — no type error, but also no first-class support.

**Implication for the WebAuthn work:** you cannot import WebAuthn request/response
types from the SDK. Options (decide during design):
  1. Hand-author the request/response interfaces in the target files (matching the
     current AWS API shape), OR
  2. Bump `aws-sdk` to a version that includes the WebAuthn model (bigger change;
     verify nothing else breaks — the whole codebase pins v2 types).

The `WEB_AUTHN` **challenge** itself can be added to
`src/targets/respondToAuthChallenge.ts` in the existing `if/else if` chain
(lines 112–187) as a new branch, since `ChallengeNameType` already accepts
arbitrary strings.

---

## "How to add a new target" — derived recipe

For each new operation `Foo`:

1. **Create `src/targets/foo.ts`:**
   ```ts
   import type { FooRequest, FooResponse } from "aws-sdk/clients/cognitoidentityserviceprovider"; // or hand-authored types for WebAuthn
   import type { Services } from "../services";
   import type { Target } from "./Target";
   // import needed errors from "../errors"

   export type FooTarget = Target<FooRequest, FooResponse>;
   type FooServices = Pick<Services, "cognito" /* + clock, etc. as needed */>;

   export const Foo =
     ({ cognito }: FooServices): FooTarget =>
     async (ctx, req) => {
       // admin op: const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
       // user op:  decode req.AccessToken -> getUserPoolForClientId(decoded.client_id)
       const user = await userPool.getUserByUsername(ctx, /* username or decoded.sub */);
       if (!user) throw new UserNotFoundError();
       await userPool.saveUser(ctx, { ...user, /* mutation */ });
       return {};
     };
   ```
2. **Register** in `src/targets/targets.ts`: add the import (alphabetical) and the
   key in the `Targets` object.
3. **Write `src/targets/foo.test.ts`** using `newMockCognitoService` +
   `newMockUserPoolService` + `TestContext` + `TDB` (+ `signAccessToken` helper if
   access-token based).
4. Run `task fmt && task test && task lint` (repo uses Taskfile, biome for
   lint/format — note `biome-ignore` comments in Router.ts).

Per-operation notes for this task:
- **GlobalSignOut**: `Pick<Services,"cognito">`; access-token flow; set
  `RefreshTokens: []`; return `{}`.
- **AdminUserGlobalSignOut**: `Pick<Services,"cognito">`; `getUserPool(UserPoolId)`
  + `getUserByUsername(Username)`; set `RefreshTokens: []`; return `{}`.
- **AdminSetUserMFAPreference**: mirror `setUserMFAPreference.ts` logic but resolve
  user by `UserPoolId`+`Username`. Consider extracting the shared MFA-mutation
  logic to avoid duplication (but per CLAUDE.md, no versioned dup names).
- **WebAuthn family**: hand-author req/res types (SDK lacks them); add
  `WebAuthnCredentials` to the `User` interface
  (`src/services/userPoolService.ts` near `SoftwareTokenMfaConfiguration`);
  store/list/delete via `saveUser`. `StartWebAuthnRegistration` returns a
  challenge/options blob; `CompleteWebAuthnRegistration` persists the credential.
- **WEB_AUTHN challenge**: new branch in `respondToAuthChallenge.ts` if/else chain
  (and likely a branch in `initiateAuth.ts` / `adminInitiateAuth.ts` to *issue*
  the challenge).

---

## Open questions

1. **WebAuthn types**: hand-author the request/response interfaces, or bump
   `aws-sdk` to a WebAuthn-aware version? The whole repo pins v2 types, so a bump
   is a wide blast radius. Recommendation leans toward hand-authored types to keep
   the change contained — needs a decision.
2. **WebAuthn crypto depth**: does cognito-local need real WebAuthn attestation
   verification, or just enough to round-trip the API shape for local dev? The
   existing TOTP support (`src/services/totp.ts`) does real verification, but SMS
   MFA just compares a stored code. Scope decision needed.
3. **Access-token invalidation**: GlobalSignOut cannot revoke stateless JWT access
   tokens (only refresh tokens are stored). Confirm this limitation is acceptable
   (it matches existing `RevokeToken` behaviour).
4. **Where to issue the WEB_AUTHN challenge**: which auth flow(s) in
   `initiateAuth.ts` / `adminInitiateAuth.ts` should surface a `WEB_AUTHN`
   challenge, and under what user/pool conditions?
5. **AdminSetUserMFAPreference dedup**: extract shared MFA-mutation helper from
   `setUserMFAPreference.ts`? Needs to respect the "no versioned function names"
   rule.
6. **Integration tests**: add `integration-tests/` coverage for the new targets,
   or rely on the per-target unit tests + the auto-covered Router registration
   test? Existing new targets mostly ship with unit tests only.
</content>
</invoke>
