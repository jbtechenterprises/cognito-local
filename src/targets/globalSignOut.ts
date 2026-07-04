import type {
  GlobalSignOutRequest,
  GlobalSignOutResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { Services } from "../services";
import { decodeToken } from "../services/tokenGenerator";
import type { Target } from "./Target";

export type GlobalSignOutTarget = Target<
  GlobalSignOutRequest,
  GlobalSignOutResponse
>;

type GlobalSignOutServices = Pick<Services, "cognito">;

/**
 * GlobalSignOut signs a user out of all sessions by clearing every refresh token
 * on their record. Access/ID tokens are stateless JWTs and cannot be revoked
 * server-side, so already-issued access tokens remain valid until they expire —
 * the same limitation as RevokeToken, acceptable for a local emulator.
 */
export const GlobalSignOut =
  ({ cognito }: GlobalSignOutServices): GlobalSignOutTarget =>
  async (ctx, req) => {
    if (!req.AccessToken) {
      throw new InvalidParameterError("Missing required parameter AccessToken");
    }

    const decoded = decodeToken(req.AccessToken);
    if (!decoded) {
      throw new InvalidParameterError();
    }

    const userPool = await cognito.getUserPoolForClientId(
      ctx,
      decoded.client_id,
    );
    const user = await userPool.getUserByUsername(ctx, decoded.sub);
    if (!user) {
      throw new NotAuthorizedError();
    }

    await userPool.saveUser(ctx, { ...user, RefreshTokens: [] });

    return {};
  };
