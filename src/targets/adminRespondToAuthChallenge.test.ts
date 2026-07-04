import {
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  type MockedObject,
  vi,
} from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockChallengeSessionStore } from "../__tests__/mockChallengeSessionStore";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type {
  CognitoService,
  Messages,
  Triggers,
  UserPoolService,
} from "../services";
import type { ChallengeSessionStore } from "../services/challengeSessionStore";
import type { TokenGenerator } from "../services/tokenGenerator";
import { generateSecret, generate as genTotp } from "../services/totp";
import {
  AdminRespondToAuthChallenge,
  type AdminRespondToAuthChallengeTarget,
} from "./adminRespondToAuthChallenge";

const currentDate = new Date();

describe("AdminRespondToAuthChallenge target", () => {
  let adminRespondToAuthChallenge: AdminRespondToAuthChallengeTarget;
  let mockCognitoService: MockedObject<CognitoService>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTriggers: MockedObject<Triggers>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockOtp: Mock<() => string>;
  let mockChallengeSessionStore: MockedObject<ChallengeSessionStore>;
  let clock: ClockFake;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    clock = new ClockFake(currentDate);
    mockTokenGenerator = newMockTokenGenerator();
    mockTriggers = newMockTriggers();
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    mockMessages = newMockMessages();
    mockOtp = vi.fn().mockReturnValue("123456");
    mockChallengeSessionStore = newMockChallengeSessionStore();

    mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);

    adminRespondToAuthChallenge = AdminRespondToAuthChallenge({
      challengeSessionStore: mockChallengeSessionStore,
      clock,
      cognito: mockCognitoService,
      messages: mockMessages,
      otp: mockOtp,
      tokenGenerator: mockTokenGenerator,
      triggers: mockTriggers,
    });
  });

  it("resolves the user pool by UserPoolId (admin addressing)", async () => {
    const secret = generateSecret();
    const user = TDB.user({
      UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
      SoftwareTokenMfaConfiguration: {
        Secret: secret,
        Verified: true,
      },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "a",
      IdToken: "i",
      RefreshToken: "r",
    });

    await adminRespondToAuthChallenge(TestContext, {
      UserPoolId: userPoolClient.UserPoolId,
      ClientId: userPoolClient.ClientId,
      ChallengeName: "SOFTWARE_TOKEN_MFA",
      Session: "sess",
      ChallengeResponses: {
        USERNAME: user.Username,
        SOFTWARE_TOKEN_MFA_CODE: genTotp(secret),
      },
    });

    expect(mockCognitoService.getUserPool).toHaveBeenCalledWith(
      TestContext,
      userPoolClient.UserPoolId,
    );
  });

  it("completes the MFA_SETUP challenge once the software token is verified", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
    mockChallengeSessionStore.get.mockReturnValue({
      userPoolId: userPoolClient.UserPoolId,
      clientId: userPoolClient.ClientId,
      username: user.Username,
      challengeName: "MFA_SETUP",
      verified: true,
    });
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "a",
      IdToken: "i",
      RefreshToken: "r",
    });

    const result = await adminRespondToAuthChallenge(TestContext, {
      UserPoolId: userPoolClient.UserPoolId,
      ClientId: userPoolClient.ClientId,
      ChallengeName: "MFA_SETUP",
      Session: "sess",
      ChallengeResponses: {
        USERNAME: user.Username,
      },
    });

    expect(result.AuthenticationResult?.AccessToken).toEqual("a");
    expect(mockChallengeSessionStore.delete).toHaveBeenCalledWith("sess");
  });

  it("rejects an MFA_SETUP challenge whose session was never verified", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    mockChallengeSessionStore.get.mockReturnValue({
      userPoolId: userPoolClient.UserPoolId,
      clientId: userPoolClient.ClientId,
      username: user.Username,
      challengeName: "MFA_SETUP",
      verified: false,
    });

    await expect(
      adminRespondToAuthChallenge(TestContext, {
        UserPoolId: userPoolClient.UserPoolId,
        ClientId: userPoolClient.ClientId,
        ChallengeName: "MFA_SETUP",
        Session: "sess",
        ChallengeResponses: {
          USERNAME: user.Username,
        },
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("rejects when the user does not exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      adminRespondToAuthChallenge(TestContext, {
        UserPoolId: userPoolClient.UserPoolId,
        ClientId: userPoolClient.ClientId,
        ChallengeName: "MFA_SETUP",
        Session: "sess",
        ChallengeResponses: {
          USERNAME: "nobody",
        },
      }),
    ).rejects.toBeInstanceOf(NotAuthorizedError);
  });
});
