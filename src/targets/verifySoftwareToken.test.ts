import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockChallengeSessionStore } from "../__tests__/mockChallengeSessionStore";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
} from "../errors";
import type { UserPoolService } from "../services";
import { generate, generateSecret } from "../services/totp";
import {
  VerifySoftwareToken,
  type VerifySoftwareTokenTarget,
} from "./verifySoftwareToken";

describe("VerifySoftwareToken target", () => {
  let verifySoftwareToken: VerifySoftwareTokenTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockChallengeSessionStore: ReturnType<
    typeof newMockChallengeSessionStore
  >;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    mockChallengeSessionStore = newMockChallengeSessionStore();
    verifySoftwareToken = VerifySoftwareToken({
      challengeSessionStore: mockChallengeSessionStore,
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("verifies a correct code and marks the secret verified", async () => {
    const secret = generateSecret();
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: secret, Verified: false },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await verifySoftwareToken(TestContext, {
      AccessToken: signAccessToken(user.Username),
      UserCode: generate(secret),
      FriendlyDeviceName: "iPhone",
    });

    expect(result.Status).toBe("SUCCESS");
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        SoftwareTokenMfaConfiguration: {
          Secret: secret,
          Verified: true,
          FriendlyDeviceName: "iPhone",
        },
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
      }),
    );
  });

  it("rejects a wrong code", async () => {
    const secret = generateSecret();
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: secret, Verified: false },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      verifySoftwareToken(TestContext, {
        AccessToken: signAccessToken(user.Username),
        UserCode: "000000",
      }),
    ).rejects.toBeInstanceOf(CodeMismatchError);
    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });

  it("rejects when the user has no associated secret", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      verifySoftwareToken(TestContext, {
        AccessToken: signAccessToken(user.Username),
        UserCode: "123456",
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  describe("via MFA_SETUP Session", () => {
    it("rejects when the session is missing or not an MFA_SETUP session", async () => {
      mockChallengeSessionStore.get.mockReturnValue(null);

      await expect(
        verifySoftwareToken(TestContext, {
          Session: "sess",
          UserCode: "123456",
        }),
      ).rejects.toBeInstanceOf(NotAuthorizedError);
    });

    it("verifies the code and marks the session verified", async () => {
      const secret = generateSecret();
      const user = TDB.user({
        SoftwareTokenMfaConfiguration: { Secret: secret, Verified: false },
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockChallengeSessionStore.get.mockReturnValue({
        userPoolId: "test-pool",
        clientId: "test-client",
        username: user.Username,
        challengeName: "MFA_SETUP",
        secret,
      });

      const result = await verifySoftwareToken(TestContext, {
        Session: "sess",
        UserCode: generate(secret),
      });

      expect(result.Status).toBe("SUCCESS");
      expect(result.Session).toEqual("sess");
      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          SoftwareTokenMfaConfiguration: expect.objectContaining({
            Secret: secret,
            Verified: true,
          }),
          UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        }),
      );
      expect(mockChallengeSessionStore.update).toHaveBeenCalledWith("sess", {
        verified: true,
      });
    });
  });
});
