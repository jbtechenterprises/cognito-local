import type {
  AssociateSoftwareTokenRequest,
  AssociateSoftwareTokenResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { Services, UserPoolService } from "../services";
import { decodeToken } from "../services/tokenGenerator";
import { generateSecret } from "../services/totp";
import type { Target } from "./Target";

export type AssociateSoftwareTokenTarget = Target<
  AssociateSoftwareTokenRequest,
  AssociateSoftwareTokenResponse
>;

type AssociateSoftwareTokenServices = Pick<
  Services,
  "challengeSessionStore" | "cognito"
>;

export const AssociateSoftwareToken =
  ({
    challengeSessionStore,
    cognito,
  }: AssociateSoftwareTokenServices): AssociateSoftwareTokenTarget =>
  async (ctx, req) => {
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

    const secret = generateSecret();
    await userPool.saveUser(ctx, {
      ...user,
      SoftwareTokenMfaConfiguration: {
        Secret: secret,
        Verified: false,
      },
    });

    if (req.Session) {
      challengeSessionStore.update(req.Session, { secret, verified: false });
    }

    return {
      SecretCode: secret,
      // Echo the session so the client can carry it into VerifySoftwareToken.
      ...(req.Session ? { Session: req.Session } : {}),
    };
  };
