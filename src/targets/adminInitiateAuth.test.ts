import {
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  type MockedObject,
  vi,
} from "vitest";
import { newMockChallengeSessionStore } from "../__tests__/mockChallengeSessionStore";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import type {
  CognitoService,
  Messages,
  Triggers,
  UserPoolService,
} from "../services";
import type { ChallengeSessionStore } from "../services/challengeSessionStore";
import type { TokenGenerator } from "../services/tokenGenerator";
import {
  AdminInitiateAuth,
  type AdminInitiateAuthTarget,
} from "./adminInitiateAuth";

describe("AdminInitiateAuth target", () => {
  let adminInitiateAuth: AdminInitiateAuthTarget;

  let mockCognitoService: MockedObject<CognitoService>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTriggers: MockedObject<Triggers>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockOtp: Mock<() => string>;
  let mockChallengeSessionStore: MockedObject<ChallengeSessionStore>;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);
    mockTriggers = newMockTriggers();
    mockTokenGenerator = newMockTokenGenerator();
    mockMessages = newMockMessages();
    mockOtp = vi.fn().mockReturnValue("123456");
    mockChallengeSessionStore = newMockChallengeSessionStore();
    adminInitiateAuth = AdminInitiateAuth({
      challengeSessionStore: mockChallengeSessionStore,
      triggers: mockTriggers,
      cognito: mockCognitoService,
      messages: mockMessages,
      otp: mockOtp,
      tokenGenerator: mockTokenGenerator,
    });
  });

  it("create tokens with username, password and admin user password auth flow", async () => {
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
    });

    const existingUser = TDB.user();

    mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

    const response = await adminInitiateAuth(TestContext, {
      AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
      ClientId: userPoolClient.ClientId,
      UserPoolId: userPoolClient.UserPoolId,
      AuthParameters: {
        USERNAME: existingUser.Username,
        PASSWORD: existingUser.Password,
      },
      ClientMetadata: {
        client: "metadata",
      },
    });

    expect(mockUserPoolService.storeRefreshToken).toHaveBeenCalledWith(
      TestContext,
      response.AuthenticationResult?.RefreshToken,
      existingUser,
    );

    expect(response.AuthenticationResult?.AccessToken).toEqual("access");
    expect(response.AuthenticationResult?.IdToken).toEqual("id");
    expect(response.AuthenticationResult?.RefreshToken).toEqual("refresh");

    expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
      TestContext,
      existingUser,
      [],
      userPoolClient,
      {
        client: "metadata",
      },
      "Authentication",
    );
  });

  describe("when the pool requires MFA (MfaConfiguration=ON)", () => {
    beforeEach(() => {
      mockUserPoolService.options.MfaConfiguration = "ON";
    });

    it("forces enrollment with an MFA_SETUP challenge for an unenrolled user", async () => {
      const user = TDB.user({
        MFAOptions: undefined,
        UserMFASettingList: undefined,
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockChallengeSessionStore.create.mockReturnValue("session-id");

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: user.Username,
          PASSWORD: user.Password,
        },
      });

      expect(response.ChallengeName).toEqual("MFA_SETUP");
      expect(response.Session).toEqual("session-id");
      expect(response.ChallengeParameters).toEqual({
        USER_ID_FOR_SRP: user.Username,
        MFAS_CAN_SETUP: JSON.stringify(["SOFTWARE_TOKEN_MFA"]),
      });
      expect(response.AuthenticationResult).toBeUndefined();
      expect(mockChallengeSessionStore.create).toHaveBeenCalledWith({
        userPoolId: userPoolClient.UserPoolId,
        clientId: userPoolClient.ClientId,
        username: user.Username,
        challengeName: "MFA_SETUP",
      });
      expect(mockTokenGenerator.generate).not.toHaveBeenCalled();
    });

    it("issues a SOFTWARE_TOKEN_MFA challenge for an already-enrolled user", async () => {
      const user = TDB.user({
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        SoftwareTokenMfaConfiguration: {
          Secret: "secret",
          Verified: true,
        },
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: user.Username,
          PASSWORD: user.Password,
        },
      });

      expect(response.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
      expect(response.ChallengeParameters).toEqual({
        USER_ID_FOR_SRP: user.Username,
      });
      expect(response.AuthenticationResult).toBeUndefined();
      expect(mockTokenGenerator.generate).not.toHaveBeenCalled();
    });
  });

  it("supports REFRESH_TOKEN_AUTH", async () => {
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
    });

    const existingUser = TDB.user({
      RefreshTokens: ["refresh token"],
    });

    mockUserPoolService.getUserByRefreshToken.mockResolvedValue(existingUser);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

    const response = await adminInitiateAuth(TestContext, {
      AuthFlow: "REFRESH_TOKEN_AUTH",
      ClientId: userPoolClient.ClientId,
      UserPoolId: userPoolClient.UserPoolId,
      AuthParameters: {
        REFRESH_TOKEN: "refresh token",
      },
      ClientMetadata: {
        client: "metadata",
      },
    });

    expect(mockUserPoolService.getUserByRefreshToken).toHaveBeenCalledWith(
      TestContext,
      "refresh token",
    );
    expect(mockUserPoolService.storeRefreshToken).not.toHaveBeenCalled();

    expect(response.AuthenticationResult?.AccessToken).toEqual("access");
    expect(response.AuthenticationResult?.IdToken).toEqual("id");

    // does not return a refresh token as part of a refresh token flow
    expect(response.AuthenticationResult?.RefreshToken).not.toBeDefined();

    expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
      TestContext,
      existingUser,
      [],
      userPoolClient,
      {
        client: "metadata",
      },
      "RefreshTokens",
    );
  });
});
