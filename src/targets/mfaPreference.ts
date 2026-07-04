import type {
  SMSMfaSettingsType,
  SoftwareTokenMfaSettingsType,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { InvalidParameterError } from "../errors";
import type { User } from "../services/userPoolService";

/**
 * applyMfaPreference resolves a user's MFA preference update shared by both
 * SetUserMFAPreference (access-token addressed) and AdminSetUserMFAPreference
 * (pool addressed). It returns the updated user; it does not persist. Throws
 * InvalidParameterError when a requested setting is not permitted.
 */
export const applyMfaPreference = (
  user: User,
  sms: SMSMfaSettingsType | undefined,
  software: SoftwareTokenMfaSettingsType | undefined,
): User => {
  if (software?.Enabled && !user.SoftwareTokenMfaConfiguration?.Verified) {
    throw new InvalidParameterError("User has not verified software token MFA");
  }

  const methods = new Set(user.UserMFASettingList ?? []);
  if (sms) {
    if (sms.Enabled) methods.add("SMS_MFA");
    else methods.delete("SMS_MFA");
  }
  if (software) {
    if (software.Enabled) methods.add("SOFTWARE_TOKEN_MFA");
    else methods.delete("SOFTWARE_TOKEN_MFA");
  }

  const preferred = sms?.PreferredMfa
    ? "SMS_MFA"
    : software?.PreferredMfa
      ? "SOFTWARE_TOKEN_MFA"
      : undefined;

  if (preferred && !methods.has(preferred)) {
    throw new InvalidParameterError(
      `Cannot set ${preferred} as preferred — it is not enabled`,
    );
  }

  return {
    ...user,
    UserMFASettingList: [...methods],
    PreferredMfaSetting: preferred,
  };
};
