import type {
  AdminSetUserMFAPreferenceRequest,
  AdminSetUserMFAPreferenceResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { applyMfaPreference } from "./mfaPreference";
import type { Target } from "./Target";

export type AdminSetUserMFAPreferenceTarget = Target<
  AdminSetUserMFAPreferenceRequest,
  AdminSetUserMFAPreferenceResponse
>;

type AdminSetUserMFAPreferenceServices = Pick<Services, "cognito">;

/**
 * AdminSetUserMFAPreference mirrors SetUserMFAPreference but is pool-addressed:
 * the user is resolved by UserPoolId + Username (admin credentials) rather than
 * by access token. The preference mutation itself is shared via applyMfaPreference.
 */
export const AdminSetUserMFAPreference =
  ({
    cognito,
  }: AdminSetUserMFAPreferenceServices): AdminSetUserMFAPreferenceTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist");
    }

    await userPool.saveUser(
      ctx,
      applyMfaPreference(
        user,
        req.SMSMfaSettings,
        req.SoftwareTokenMfaSettings,
      ),
    );

    return {};
  };
