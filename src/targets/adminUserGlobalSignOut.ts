import type {
  AdminUserGlobalSignOutRequest,
  AdminUserGlobalSignOutResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import type { Target } from "./Target";

export type AdminUserGlobalSignOutTarget = Target<
  AdminUserGlobalSignOutRequest,
  AdminUserGlobalSignOutResponse
>;

type AdminUserGlobalSignOutServices = Pick<Services, "cognito">;

/**
 * AdminUserGlobalSignOut is the pool-addressed counterpart to GlobalSignOut: it
 * clears every refresh token for the user identified by UserPoolId + Username.
 * Stateless access tokens cannot be revoked (see GlobalSignOut).
 */
export const AdminUserGlobalSignOut =
  ({ cognito }: AdminUserGlobalSignOutServices): AdminUserGlobalSignOutTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist");
    }

    await userPool.saveUser(ctx, { ...user, RefreshTokens: [] });

    return {};
  };
