import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, UserNotFoundError } from "../errors";
import type { UserPoolService } from "../services";
import {
  AdminSetUserMFAPreference,
  type AdminSetUserMFAPreferenceTarget,
} from "./adminSetUserMFAPreference";

describe("AdminSetUserMFAPreference target", () => {
  let adminSetUserMFAPreference: AdminSetUserMFAPreferenceTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    adminSetUserMFAPreference = AdminSetUserMFAPreference({
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("resolves the user by UserPoolId + Username and enables SMS_MFA", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await adminSetUserMFAPreference(TestContext, {
      UserPoolId: "test",
      Username: user.Username,
      SMSMfaSettings: { Enabled: true, PreferredMfa: true },
    });

    expect(mockUserPoolService.getUserByUsername).toHaveBeenCalledWith(
      TestContext,
      user.Username,
    );
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        UserMFASettingList: ["SMS_MFA"],
        PreferredMfaSetting: "SMS_MFA",
      }),
    );
  });

  it("rejects enabling SOFTWARE_TOKEN_MFA without a verified secret", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      adminSetUserMFAPreference(TestContext, {
        UserPoolId: "test",
        Username: user.Username,
        SoftwareTokenMfaSettings: { Enabled: true },
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("throws when the user does not exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      adminSetUserMFAPreference(TestContext, {
        UserPoolId: "test",
        Username: "nobody",
        SMSMfaSettings: { Enabled: true },
      }),
    ).rejects.toBeInstanceOf(UserNotFoundError);
  });
});
