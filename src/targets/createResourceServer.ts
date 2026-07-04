import type {
  CreateResourceServerRequest,
  CreateResourceServerResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import type { Services } from "../services";
import type { ResourceServer } from "../services/userPoolService";
import { resourceServerToResponseObject } from "./responses";
import type { Target } from "./Target";
import { assertRequiredParameter } from "./utils/assertions";

export type CreateResourceServerTarget = Target<
  CreateResourceServerRequest,
  CreateResourceServerResponse
>;

type CreateResourceServerServices = Pick<Services, "cognito">;

export const CreateResourceServer =
  ({ cognito }: CreateResourceServerServices): CreateResourceServerTarget =>
  async (ctx, req) => {
    assertRequiredParameter("Identifier", req.Identifier);
    assertRequiredParameter("Name", req.Name);

    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);

    const resourceServer: ResourceServer = {
      Identifier: req.Identifier,
      Name: req.Name,
      Scopes: req.Scopes,
    };

    await userPool.saveResourceServer(ctx, resourceServer);

    return {
      ResourceServer: resourceServerToResponseObject(req.UserPoolId)(
        resourceServer,
      ),
    };
  };
