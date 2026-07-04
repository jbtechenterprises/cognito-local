import type {
  AdminRespondToAuthChallengeRequest,
  AdminRespondToAuthChallengeResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import {
  type RespondToAuthChallengeService,
  respondToAuthChallengeFlow,
} from "./respondToAuthChallenge";
import type { Target } from "./Target";

export type AdminRespondToAuthChallengeTarget = Target<
  AdminRespondToAuthChallengeRequest,
  AdminRespondToAuthChallengeResponse
>;

type AdminRespondToAuthChallengeServices = RespondToAuthChallengeService;

/**
 * AdminRespondToAuthChallenge mirrors RespondToAuthChallenge but is
 * pool-addressed: the user pool is resolved by UserPoolId (admin credentials)
 * rather than by the app client id. The challenge-response logic itself is
 * shared via respondToAuthChallengeFlow.
 */
export const AdminRespondToAuthChallenge =
  (
    services: AdminRespondToAuthChallengeServices,
  ): AdminRespondToAuthChallengeTarget =>
  async (ctx, req) => {
    const userPool = await services.cognito.getUserPool(ctx, req.UserPoolId);
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
