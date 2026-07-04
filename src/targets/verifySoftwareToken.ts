import type {
  VerifySoftwareTokenRequest,
  VerifySoftwareTokenResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
} from "../errors";
import type { Services, UserPoolService } from "../services";
import { decodeToken } from "../services/tokenGenerator";
import { verify } from "../services/totp";
import type { Target } from "./Target";

export type VerifySoftwareTokenTarget = Target<
  VerifySoftwareTokenRequest,
  VerifySoftwareTokenResponse
>;

type VerifySoftwareTokenServices = Pick<
  Services,
  "challengeSessionStore" | "cognito"
>;

export const VerifySoftwareToken =
  ({
    challengeSessionStore,
    cognito,
  }: VerifySoftwareTokenServices): VerifySoftwareTokenTarget =>
  async (ctx, req) => {
    if (!req.UserCode) {
      throw new InvalidParameterError("Missing required parameter UserCode");
    }
    if (!req.AccessToken && !req.Session) {
      throw new InvalidParameterError(
        "Either AccessToken or Session is required",
      );
    }

    // Resolve the target user either from an AccessToken (already-authenticated
    // enrollment) or from an MFA_SETUP challenge Session (forced first-login
    // enrollment).
    let user: Awaited<ReturnType<UserPoolService["getUserByUsername"]>>;
    let userPool: UserPoolService;
    if (req.AccessToken) {
      const decoded = decodeToken(req.AccessToken);
      if (!decoded) {
        throw new InvalidParameterError();
      }
      userPool = await cognito.getUserPoolForClientId(ctx, decoded.client_id);
      user = await userPool.getUserByUsername(ctx, decoded.sub);
    } else {
      const session = challengeSessionStore.get(req.Session as string);
      if (!session || session.challengeName !== "MFA_SETUP") {
        throw new NotAuthorizedError();
      }
      userPool = await cognito.getUserPool(ctx, session.userPoolId);
      user = await userPool.getUserByUsername(ctx, session.username);
    }

    if (!user) {
      throw new NotAuthorizedError();
    }

    const secret = user.SoftwareTokenMfaConfiguration?.Secret;
    if (!secret) {
      throw new InvalidParameterError(
        "User has not associated a software token",
      );
    }

    if (!verify(secret, req.UserCode)) {
      throw new CodeMismatchError();
    }

    const existingMethods = user.UserMFASettingList ?? [];
    const UserMFASettingList = existingMethods.includes("SOFTWARE_TOKEN_MFA")
      ? existingMethods
      : [...existingMethods, "SOFTWARE_TOKEN_MFA"];

    await userPool.saveUser(ctx, {
      ...user,
      SoftwareTokenMfaConfiguration: {
        Secret: secret,
        Verified: true,
        FriendlyDeviceName:
          req.FriendlyDeviceName ??
          user.SoftwareTokenMfaConfiguration?.FriendlyDeviceName,
      },
      UserMFASettingList,
    });

    // Mark the MFA_SETUP session as verified so RespondToAuthChallenge can
    // finalize the sign-in and issue tokens.
    if (req.Session) {
      challengeSessionStore.update(req.Session, { verified: true });
    }

    return {
      Status: "SUCCESS",
      Session: req.Session,
    };
  };
