import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockChallengeSessionStore } from "../__tests__/mockChallengeSessionStore";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { UserPoolService } from "../services";
import {
  AssociateSoftwareToken,
  type AssociateSoftwareTokenTarget,
} from "./associateSoftwareToken";

describe("AssociateSoftwareToken target", () => {
  let associateSoftwareToken: AssociateSoftwareTokenTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockChallengeSessionStore: ReturnType<
    typeof newMockChallengeSessionStore
  >;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    mockChallengeSessionStore = newMockChallengeSessionStore();
    associateSoftwareToken = AssociateSoftwareToken({
      challengeSessionStore: mockChallengeSessionStore,
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("rejects when neither AccessToken nor Session provided", async () => {
    await expect(
      associateSoftwareToken(TestContext, {}),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("generates and stores a TOTP secret for the authed user", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await associateSoftwareToken(TestContext, {
      AccessToken: signAccessToken(user.Username),
    });

    expect(result.SecretCode).toMatch(/^[A-Z2-7]+=*$/);
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        Username: user.Username,
        SoftwareTokenMfaConfiguration: {
          Secret: result.SecretCode,
          Verified: false,
        },
      }),
    );
  });

  describe("via MFA_SETUP Session", () => {
    it("rejects when the session is missing or not an MFA_SETUP session", async () => {
      mockChallengeSessionStore.get.mockReturnValue(null);

      await expect(
        associateSoftwareToken(TestContext, { Session: "sess" }),
      ).rejects.toBeInstanceOf(NotAuthorizedError);
    });

    it("generates a secret and threads the session forward", async () => {
      const user = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockChallengeSessionStore.get.mockReturnValue({
        userPoolId: "test-pool",
        clientId: "test-client",
        username: user.Username,
        challengeName: "MFA_SETUP",
      });

      const result = await associateSoftwareToken(TestContext, {
        Session: "sess",
      });

      expect(result.SecretCode).toMatch(/^[A-Z2-7]+=*$/);
      expect(result.Session).toEqual("sess");
      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          Username: user.Username,
          SoftwareTokenMfaConfiguration: {
            Secret: result.SecretCode,
            Verified: false,
          },
        }),
      );
      expect(mockChallengeSessionStore.update).toHaveBeenCalledWith("sess", {
        secret: result.SecretCode,
        verified: false,
      });
    });
  });
});
