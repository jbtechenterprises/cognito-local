import { createPrivateKey } from "node:crypto";
import type { StringMap } from "aws-lambda/trigger/cognito-user-pool-trigger/_common";
import type { GroupOverrideDetails } from "aws-lambda/trigger/cognito-user-pool-trigger/pre-token-generation";
import type { TimeUnitsType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import { decodeJwt, type JWTPayload, SignJWT } from "jose";
import * as uuid from "uuid";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { AppClient } from "./appClient";
import type { Clock } from "./clock";
import type { Context } from "./context";
import type { Triggers } from "./triggers";
import {
  attributesToRecord,
  attributeValue,
  customAttributes,
  type User,
} from "./userPoolService";

export interface TokenConfig {
  IssuerDomain?: string;
}

export interface Token {
  client_id: string;
  iss: string;
  sub: string;
  token_use: string;
  username: string;
  event_id: string;
  scope: string;
  auth_time: Date;
  jti: string;
}

interface TokenOverrides {
  claimsToAddOrOverride?: StringMap | undefined;
  claimsToSuppress?: string[] | undefined;
  groupOverrideDetails?: GroupOverrideDetails | undefined;
}

const RESERVED_CLAIMS = [
  "acr",
  "amr",
  "aud",
  "at_hash",
  "auth_time",
  "azp",
  "cognito:username",
  "exp",
  "iat",
  "identities",
  "iss",
  "jti",
  "nbf",
  "nonce",
  "origin_jti",
  "sub",
  "token_use",
];

type RawToken = Record<
  string,
  string | number | boolean | undefined | readonly string[]
>;

const applyTokenOverrides = (
  token: RawToken,
  overrides: TokenOverrides,
): RawToken => {
  // TODO: support group overrides

  const claimsToSuppress = (overrides?.claimsToSuppress ?? []).filter(
    (claim) => !RESERVED_CLAIMS.includes(claim),
  );

  const claimsToOverride = Object.entries(
    overrides?.claimsToAddOrOverride ?? [],
  ).filter(([claim]) => !RESERVED_CLAIMS.includes(claim));

  return Object.fromEntries(
    [...Object.entries(token), ...claimsToOverride].filter(
      ([claim]) => !claimsToSuppress.includes(claim),
    ),
  );
};

export interface Tokens {
  readonly AccessToken: string;
  readonly IdToken: string;
  readonly RefreshToken: string;
}

// Machine-to-machine (client_credentials) tokens only carry an access token —
// there is no authenticated user, so no id or refresh token is issued.
export interface ClientCredentialsTokens {
  readonly AccessToken: string;
}

export interface TokenGenerator {
  generate(
    ctx: Context,
    user: User,
    userGroups: readonly string[],
    userPoolClient: AppClient,
    clientMetadata: Record<string, string> | undefined,
    source:
      | "AuthenticateDevice"
      | "Authentication"
      | "HostedAuth"
      | "NewPasswordChallenge"
      | "RefreshTokens",
  ): Promise<Tokens>;
  generateWithClientCreds(
    ctx: Context,
    userPoolClient: AppClient,
  ): Promise<ClientCredentialsTokens>;
}

const UNIT_SECONDS: Record<string, number> = {
  seconds: 1,
  minutes: 60,
  hours: 60 * 60,
  days: 24 * 60 * 60,
};

const ONE_DAY_SECONDS = 24 * 60 * 60;
const SEVEN_DAYS_SECONDS = 7 * ONE_DAY_SECONDS;

const expirationSeconds = (
  duration: number | undefined,
  unit: TimeUnitsType,
  fallbackSeconds: number,
): number => {
  if (duration === undefined) {
    return fallbackSeconds;
  }

  const unitSeconds = UNIT_SECONDS[unit];
  if (unitSeconds === undefined) {
    throw new Error(`Invalid unit: ${unit}`);
  }

  return duration * unitSeconds;
};

const privateKey = createPrivateKey(PrivateKey.pem);

const signToken = async (
  payload: RawToken,
  opts: {
    issuer: string;
    expiresAt: number;
    audience?: string;
    keyid?: string;
  },
): Promise<string> => {
  const signer = new SignJWT(payload as JWTPayload).setProtectedHeader(
    opts.keyid ? { alg: "RS256", kid: opts.keyid } : { alg: "RS256" },
  );
  signer.setIssuer(opts.issuer);
  signer.setExpirationTime(opts.expiresAt);
  if (opts.audience !== undefined) {
    signer.setAudience(opts.audience);
  }

  return signer.sign(privateKey);
};

/**
 * decodeToken decodes a JWT's claims without verifying its signature — the local
 * equivalent of the previous jwt.decode usage. Returns null on malformed input
 * so callers can surface a Cognito-shaped error instead of throwing.
 */
export const decodeToken = (token: string): Token | null => {
  try {
    return decodeJwt(token) as unknown as Token;
  } catch {
    return null;
  }
};

export class JwtTokenGenerator implements TokenGenerator {
  private readonly clock: Clock;
  private readonly triggers: Triggers;
  private readonly tokenConfig: TokenConfig;

  public constructor(
    clock: Clock,
    triggers: Triggers,
    tokenConfig: TokenConfig,
  ) {
    this.clock = clock;
    this.triggers = triggers;
    this.tokenConfig = tokenConfig;
  }

  public async generate(
    ctx: Context,
    user: User,
    userGroups: readonly string[],
    userPoolClient: AppClient,
    clientMetadata: Record<string, string> | undefined,
    source:
      | "AuthenticateDevice"
      | "Authentication"
      | "HostedAuth"
      | "NewPasswordChallenge"
      | "RefreshTokens",
  ): Promise<Tokens> {
    const eventId = uuid.v4();
    const authTime = Math.floor(this.clock.get().getTime() / 1000);
    const sub = attributeValue("sub", user.Attributes);

    const accessToken: RawToken = {
      auth_time: authTime,
      client_id: userPoolClient.ClientId,
      event_id: eventId,
      iat: authTime,
      jti: uuid.v4(),
      scope: "aws.cognito.signin.user.admin", // TODO: scopes
      sub,
      token_use: "access",
      username: user.Username,
    };
    let idToken: RawToken = {
      "cognito:username": user.Username,
      auth_time: authTime,
      email: attributeValue("email", user.Attributes),
      email_verified: Boolean(
        attributeValue("email_verified", user.Attributes) ?? false,
      ),
      event_id: eventId,
      iat: authTime,
      jti: uuid.v4(),
      sub,
      token_use: "id",
      ...attributesToRecord(customAttributes(user.Attributes)),
    };

    if (userGroups.length) {
      accessToken["cognito:groups"] = userGroups;
      idToken["cognito:groups"] = userGroups;
    }

    if (this.triggers.enabled("PreTokenGeneration")) {
      const result = await this.triggers.preTokenGeneration(ctx, {
        clientId: userPoolClient.ClientId,
        clientMetadata,
        source,
        userAttributes: user.Attributes,
        username: user.Username,
        groupConfiguration: {
          // TODO: this should be populated from the user's groups
          groupsToOverride: undefined,
          iamRolesToOverride: undefined,
          preferredRole: undefined,
        },
        userPoolId: userPoolClient.UserPoolId,
      });

      idToken = applyTokenOverrides(idToken, result.claimsOverrideDetails);
    }

    const issuer = `${this.tokenConfig.IssuerDomain}/${userPoolClient.UserPoolId}`;

    return {
      AccessToken: await signToken(accessToken, {
        issuer,
        expiresAt:
          authTime +
          expirationSeconds(
            userPoolClient.AccessTokenValidity,
            userPoolClient.TokenValidityUnits?.AccessToken ?? "hours",
            ONE_DAY_SECONDS,
          ),
        keyid: "CognitoLocal",
      }),
      IdToken: await signToken(idToken, {
        issuer,
        expiresAt:
          authTime +
          expirationSeconds(
            userPoolClient.IdTokenValidity,
            userPoolClient.TokenValidityUnits?.IdToken ?? "hours",
            ONE_DAY_SECONDS,
          ),
        audience: userPoolClient.ClientId,
        keyid: "CognitoLocal",
      }),
      // this content is for debugging purposes only
      // in reality token payload is encrypted and uses different algorithm
      RefreshToken: await signToken(
        {
          "cognito:username": user.Username,
          email: attributeValue("email", user.Attributes),
          iat: authTime,
          jti: uuid.v4(),
        },
        {
          issuer,
          expiresAt:
            authTime +
            expirationSeconds(
              userPoolClient.RefreshTokenValidity,
              userPoolClient.TokenValidityUnits?.RefreshToken ?? "days",
              SEVEN_DAYS_SECONDS,
            ),
        },
      ),
    };
  }

  public async generateWithClientCreds(
    _ctx: Context,
    userPoolClient: AppClient,
  ): Promise<ClientCredentialsTokens> {
    const eventId = uuid.v4();
    const authTime = Math.floor(this.clock.get().getTime() / 1000);

    // For M2M tokens (client_credentials flow), use a service scope
    // that distinguishes them from human user tokens.
    // Human users have "aws.cognito.signin.user.admin" scope.
    // M2M tokens use custom resource server scopes in production.
    const accessToken: RawToken = {
      auth_time: authTime,
      client_id: userPoolClient.ClientId,
      event_id: eventId,
      iat: authTime,
      jti: uuid.v4(),
      scope: "m2m/service",
      sub: userPoolClient.ClientId,
      token_use: "access",
    };

    const issuer = `${this.tokenConfig.IssuerDomain}/${userPoolClient.UserPoolId}`;

    return {
      AccessToken: await signToken(accessToken, {
        issuer,
        expiresAt:
          authTime +
          expirationSeconds(
            userPoolClient.AccessTokenValidity,
            userPoolClient.TokenValidityUnits?.AccessToken ?? "hours",
            ONE_DAY_SECONDS,
          ),
        keyid: "CognitoLocal",
      }),
    };
  }
}
