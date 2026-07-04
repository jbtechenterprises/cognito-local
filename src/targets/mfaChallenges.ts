import type { DeliveryMediumType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import { v4 } from "uuid";
import { UnsupportedError } from "../errors";
import type { Services, UserPoolService } from "../services";
import type { Context } from "../services/context";
import {
  attributeValue,
  type MFAOption,
  type User,
} from "../services/userPoolService";

/**
 * The subset of an InitiateAuth / AdminInitiateAuth response an MFA challenge
 * produces. Both {@link InitiateAuthResponse} and {@link AdminInitiateAuthResponse}
 * are structural supersets of this, so the same helpers drive the user and admin
 * sign-in flows without duplication.
 */
export interface MfaChallengeResponse {
  ChallengeName: string;
  ChallengeParameters: Record<string, string>;
  Session: string;
}

/**
 * Services needed to build an MFA challenge. Kept minimal so both InitiateAuth
 * and AdminInitiateAuth can satisfy it from their own `Pick<Services, ...>`.
 */
export type MfaChallengeServices = Pick<
  Services,
  "challengeSessionStore" | "messages" | "otp"
>;

/**
 * enabledMfaMethods derives the ordered list of MFA methods a user has enrolled,
 * preferring the explicit UserMFASettingList and falling back to legacy SMS
 * MFAOptions.
 */
export const enabledMfaMethods = (
  user: User,
): readonly ("SMS_MFA" | "SOFTWARE_TOKEN_MFA")[] => {
  const explicit = user.UserMFASettingList ?? [];
  const legacy =
    explicit.length === 0 &&
    (user.MFAOptions ?? []).some((o) => o.DeliveryMedium === "SMS")
      ? ["SMS_MFA"]
      : [];
  const methods = new Set<string>([...explicit, ...legacy]);

  const result: ("SMS_MFA" | "SOFTWARE_TOKEN_MFA")[] = [];
  if (methods.has("SMS_MFA")) result.push("SMS_MFA");
  if (methods.has("SOFTWARE_TOKEN_MFA")) result.push("SOFTWARE_TOKEN_MFA");
  return result;
};

/**
 * mfaSetupChallenge starts a forced first-login enrollment. Only software-token
 * MFA can be enrolled mid-sign-in; SMS setup requires a verified phone number
 * established out of band. The returned Session is persisted so the subsequent
 * AssociateSoftwareToken / VerifySoftwareToken / RespondToAuthChallenge requests
 * can be correlated and validated.
 */
export const mfaSetupChallenge = (
  user: User,
  clientId: string,
  userPool: UserPoolService,
  services: MfaChallengeServices,
): MfaChallengeResponse => {
  const session = services.challengeSessionStore.create({
    userPoolId: userPool.options.Id,
    clientId,
    username: user.Username,
    challengeName: "MFA_SETUP",
  });

  return {
    ChallengeName: "MFA_SETUP",
    ChallengeParameters: {
      USER_ID_FOR_SRP: user.Username,
      MFAS_CAN_SETUP: JSON.stringify(["SOFTWARE_TOKEN_MFA"]),
    },
    Session: session,
  };
};

/**
 * smsMfaChallenge delivers an SMS OTP and returns the SMS_MFA challenge. The code
 * is stored transiently on the user for later verification.
 */
export const smsMfaChallenge = async (
  ctx: Context,
  user: User,
  clientId: string,
  clientMetadata: Record<string, string> | undefined,
  userPool: UserPoolService,
  services: MfaChallengeServices,
): Promise<MfaChallengeResponse> => {
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
    clientId,
    userPool.options.Id,
    user,
    code,
    clientMetadata,
    {
      DeliveryMedium: smsMfaOption.DeliveryMedium,
      AttributeName: smsMfaOption.AttributeName,
      Destination: deliveryDestination,
    },
  );

  await userPool.saveUser(ctx, {
    ...user,
    MFACode: code,
  });

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
 * softwareTokenMfaChallenge returns the SOFTWARE_TOKEN_MFA challenge for an
 * already-enrolled user.
 */
export const softwareTokenMfaChallenge = (
  user: User,
): MfaChallengeResponse => ({
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
});

/**
 * verifyMfaChallenge selects the appropriate MFA challenge for a user who must
 * satisfy MFA to complete sign-in:
 * - no enrolled methods (forced-MFA pool) → MFA_SETUP first-login enrollment
 * - more than one method → SELECT_MFA_TYPE
 * - exactly one method → that method's challenge
 */
export const verifyMfaChallenge = async (
  ctx: Context,
  user: User,
  clientId: string,
  clientMetadata: Record<string, string> | undefined,
  userPool: UserPoolService,
  services: MfaChallengeServices,
): Promise<MfaChallengeResponse> => {
  const methods = enabledMfaMethods(user);
  if (methods.length === 0) {
    // Pool requires MFA (MfaConfiguration=ON) but the user has enrolled no
    // methods yet: force first-login enrollment via an MFA_SETUP challenge
    // rather than rejecting the sign-in.
    return mfaSetupChallenge(user, clientId, userPool, services);
  }

  if (methods.length > 1) {
    return {
      ChallengeName: "SELECT_MFA_TYPE",
      ChallengeParameters: {
        USER_ID_FOR_SRP: user.Username,
        MFAS_CAN_CHOOSE: JSON.stringify(methods),
      },
      Session: v4(),
    };
  }

  if (methods[0] === "SOFTWARE_TOKEN_MFA") {
    return softwareTokenMfaChallenge(user);
  }
  return smsMfaChallenge(
    ctx,
    user,
    clientId,
    clientMetadata,
    userPool,
    services,
  );
};

/**
 * userRequiresMfa reports whether the pool configuration + user enrollment mean
 * the sign-in must be gated behind an MFA (or MFA_SETUP) challenge.
 */
export const userRequiresMfa = (
  user: User,
  mfaConfiguration: string | undefined,
): boolean => {
  const userHasMfa =
    (user.MFAOptions ?? []).length > 0 ||
    (user.UserMFASettingList ?? []).length > 0;
  return (
    mfaConfiguration === "ON" || (mfaConfiguration !== "OFF" && userHasMfa)
  );
};
