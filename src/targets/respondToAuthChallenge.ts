import type {
  DeliveryMediumType,
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { v4 } from "uuid";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
  UnsupportedError,
} from "../errors";
import type { Services, UserPoolService } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import { verify as verifyTotp } from "../services/totp";
import {
  attributeValue,
  type MFAOption,
  type User,
} from "../services/userPoolService";
import type { Target } from "./Target";

export type RespondToAuthChallengeTarget = Target<
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse
>;

export type RespondToAuthChallengeService = Pick<
  Services,
  | "challengeSessionStore"
  | "clock"
  | "cognito"
  | "messages"
  | "otp"
  | "triggers"
  | "tokenGenerator"
>;

/**
 * The subset of a RespondToAuthChallenge / AdminRespondToAuthChallenge request
 * the shared flow reads. Both SDK request types are structural supersets, so the
 * flow drives the user and admin challenge responses without duplication.
 */
export interface RespondToAuthChallengeInput {
  ChallengeName?: string;
  Session?: string;
  ChallengeResponses?: Record<string, string>;
  ClientId: string;
  ClientMetadata?: Record<string, string>;
}

const sendSmsMfaChallenge = async (
  ctx: Context,
  req: RespondToAuthChallengeInput,
  user: User,
  userPoolId: string,
  services: RespondToAuthChallengeService,
  saveUser: (u: User) => Promise<void>,
): Promise<RespondToAuthChallengeResponse> => {
  const smsMfaOption = user.MFAOptions?.find(
    (x): x is MFAOption & { DeliveryMedium: DeliveryMediumType } =>
      x.DeliveryMedium === "SMS",
  );
  if (!smsMfaOption) {
    throw new UnsupportedError("SMS_MFA without SMS MFAOption");
  }
  const deliveryDestination = attributeValue(
    smsMfaOption.AttributeName,
    user.Attributes,
  );
  if (!deliveryDestination) {
    throw new UnsupportedError(`SMS_MFA without ${smsMfaOption.AttributeName}`);
  }

  const code = services.otp();
  await services.messages.deliver(
    ctx,
    "Authentication",
    req.ClientId,
    userPoolId,
    user,
    code,
    req.ClientMetadata,
    {
      DeliveryMedium: smsMfaOption.DeliveryMedium,
      AttributeName: smsMfaOption.AttributeName,
      Destination: deliveryDestination,
    },
  );

  await saveUser({ ...user, MFACode: code });

  return {
    ChallengeName: "SMS_MFA",
    ChallengeParameters: {
      CODE_DELIVERY_DELIVERY_MEDIUM: "SMS",
      CODE_DELIVERY_DESTINATION: deliveryDestination,
      USER_ID_FOR_SRP: user.Username,
    },
    Session: v4(),
  };
};

/**
 * respondToAuthChallengeFlow contains the full challenge-response logic shared by
 * both RespondToAuthChallenge (client-addressed) and AdminRespondToAuthChallenge
 * (pool-addressed). Callers resolve the userPool + userPoolClient however they
 * address the request and delegate the rest here.
 */
export const respondToAuthChallengeFlow = async (
  ctx: Context,
  req: RespondToAuthChallengeInput,
  userPool: UserPoolService,
  userPoolClient: AppClient | null,
  services: RespondToAuthChallengeService,
): Promise<RespondToAuthChallengeResponse> => {
  const { challengeSessionStore, clock, triggers, tokenGenerator } = services;

  if (!req.ChallengeResponses) {
    throw new InvalidParameterError(
      "Missing required parameter challenge responses",
    );
  }
  if (!req.ChallengeResponses.USERNAME) {
    throw new InvalidParameterError("Missing required parameter USERNAME");
  }
  if (!req.Session) {
    throw new InvalidParameterError("Missing required parameter Session");
  }

  const user = await userPool.getUserByUsername(
    ctx,
    req.ChallengeResponses.USERNAME,
  );
  if (!user || !userPoolClient) {
    throw new NotAuthorizedError();
  }

  if (req.ChallengeName === "SELECT_MFA_TYPE") {
    const answer = req.ChallengeResponses.ANSWER;
    if (answer === "SMS_MFA") {
      return sendSmsMfaChallenge(
        ctx,
        req,
        user,
        userPool.options.Id,
        services,
        (u) => userPool.saveUser(ctx, u),
      );
    }
    if (answer === "SOFTWARE_TOKEN_MFA") {
      return {
        ChallengeName: "SOFTWARE_TOKEN_MFA",
        ChallengeParameters: {
          USER_ID_FOR_SRP: user.Username,
          ...(user.SoftwareTokenMfaConfiguration?.FriendlyDeviceName
            ? {
                FRIENDLY_DEVICE_NAME:
                  user.SoftwareTokenMfaConfiguration.FriendlyDeviceName,
              }
            : {}),
        },
        Session: v4(),
      };
    }
    throw new InvalidParameterError(
      "SELECT_MFA_TYPE requires ANSWER of SMS_MFA or SOFTWARE_TOKEN_MFA",
    );
  }

  if (req.ChallengeName === "SMS_MFA") {
    if (user.MFACode !== req.ChallengeResponses.SMS_MFA_CODE) {
      throw new CodeMismatchError();
    }

    await userPool.saveUser(ctx, {
      ...user,
      MFACode: undefined,
      UserLastModifiedDate: clock.get(),
    });
  } else if (req.ChallengeName === "SOFTWARE_TOKEN_MFA") {
    const code = req.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE;
    const secret = user.SoftwareTokenMfaConfiguration?.Secret;
    if (
      !code ||
      !secret ||
      !user.SoftwareTokenMfaConfiguration?.Verified ||
      !verifyTotp(secret, code)
    ) {
      throw new CodeMismatchError();
    }
    await userPool.saveUser(ctx, {
      ...user,
      UserLastModifiedDate: clock.get(),
    });
  } else if (req.ChallengeName === "MFA_SETUP") {
    // Forced first-login enrollment: the client has already run
    // AssociateSoftwareToken + VerifySoftwareToken against this Session. Only
    // finalize the sign-in once that verification succeeded.
    const session = challengeSessionStore.get(req.Session);
    if (
      !session ||
      session.challengeName !== "MFA_SETUP" ||
      session.username !== user.Username
    ) {
      throw new NotAuthorizedError();
    }
    if (!session.verified) {
      throw new InvalidParameterError(
        "Software token MFA has not been verified for this session",
      );
    }

    challengeSessionStore.delete(req.Session);

    await userPool.saveUser(ctx, {
      ...user,
      UserLastModifiedDate: clock.get(),
    });
  } else if (req.ChallengeName === "NEW_PASSWORD_REQUIRED") {
    if (!req.ChallengeResponses.NEW_PASSWORD) {
      throw new InvalidParameterError(
        "Missing required parameter NEW_PASSWORD",
      );
    }

    // TODO: validate the password?
    await userPool.saveUser(ctx, {
      ...user,
      Password: req.ChallengeResponses.NEW_PASSWORD,
      UserLastModifiedDate: clock.get(),
      UserStatus: "CONFIRMED",
    });
  } else if (req.ChallengeName === "WEB_AUTHN") {
    // Test-oriented passkey assertion: accept the assertion if the user has at
    // least one registered credential. No FIDO2 signature verification is
    // performed (cognito-local does not store verifiable public keys).
    if (!(user.WebAuthnCredentials ?? []).length) {
      throw new NotAuthorizedError();
    }
    await userPool.saveUser(ctx, {
      ...user,
      UserLastModifiedDate: clock.get(),
    });
  } else {
    throw new UnsupportedError(
      `respondToAuthChallenge with ChallengeName=${req.ChallengeName}`,
    );
  }

  if (triggers.enabled("PostAuthentication")) {
    await triggers.postAuthentication(ctx, {
      clientId: req.ClientId,
      clientMetadata: req.ClientMetadata,
      source: "PostAuthentication_Authentication",
      userAttributes: user.Attributes,
      username: user.Username,
      userPoolId: userPool.options.Id,
    });
  }

  const userGroups = await userPool.listUserGroupMembership(ctx, user);

  return {
    ChallengeParameters: {},
    AuthenticationResult: await tokenGenerator.generate(
      ctx,
      user,
      userGroups,
      userPoolClient,
      req.ClientMetadata,
      "Authentication",
    ),
  };
};

export const RespondToAuthChallenge =
  (services: RespondToAuthChallengeService): RespondToAuthChallengeTarget =>
  async (ctx, req) => {
    const userPool = await services.cognito.getUserPoolForClientId(
      ctx,
      req.ClientId,
    );
    const userPoolClient = await services.cognito.getAppClient(
      ctx,
      req.ClientId,
    );

    return respondToAuthChallengeFlow(
      ctx,
      req,
      userPool,
      userPoolClient,
      services,
    );
  };
