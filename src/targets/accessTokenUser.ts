import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { CognitoService } from "../services";
import type { Context } from "../services/context";
import { decodeToken } from "../services/tokenGenerator";
import type { User, UserPoolService } from "../services/userPoolService";

/**
 * resolveUserFromAccessToken decodes a Cognito access token and loads the
 * corresponding user + pool. It centralizes the access-token → user pattern used
 * by the self-service targets (WebAuthn registration, etc.).
 */
export const resolveUserFromAccessToken = async (
  ctx: Context,
  cognito: CognitoService,
  accessToken: string | undefined,
): Promise<{ userPool: UserPoolService; user: User }> => {
  if (!accessToken) {
    throw new InvalidParameterError("Missing required parameter AccessToken");
  }

  const decoded = decodeToken(accessToken);
  if (!decoded) {
    throw new InvalidParameterError();
  }

  const userPool = await cognito.getUserPoolForClientId(ctx, decoded.client_id);
  const user = await userPool.getUserByUsername(ctx, decoded.sub);
  if (!user) {
    throw new NotAuthorizedError();
  }

  return { userPool, user };
};
