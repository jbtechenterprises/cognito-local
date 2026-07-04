import type { DeleteUserRequest } from "aws-sdk/clients/cognitoidentityserviceprovider";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { Services } from "../services";
import { decodeToken } from "../services/tokenGenerator";
import type { Target } from "./Target";

export type DeleteUserTarget = Target<DeleteUserRequest, object>;

type DeleteUserServices = Pick<Services, "cognito">;

export const DeleteUser =
  ({ cognito }: DeleteUserServices): DeleteUserTarget =>
  async (ctx, req) => {
    const decodedToken = decodeToken(req.AccessToken);
    if (!decodedToken) {
      ctx.logger.info("Unable to decode token");
      throw new InvalidParameterError();
    }

    const userPool = await cognito.getUserPoolForClientId(
      ctx,
      decodedToken.client_id,
    );
    const user = await userPool.getUserByUsername(ctx, decodedToken.sub);
    if (!user) {
      throw new NotAuthorizedError();
    }

    await userPool.deleteUser(ctx, user);

    return {};
  };
