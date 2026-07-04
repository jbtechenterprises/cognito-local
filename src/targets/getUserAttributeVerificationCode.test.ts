import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, UserNotFoundError } from "../errors";
import type { Messages, UserPoolService } from "../services";
import { attribute, attributeValue } from "../services/userPoolService";
import {
  GetUserAttributeVerificationCode,
  type GetUserAttributeVerificationCodeTarget,
} from "./getUserAttributeVerificationCode";

const validToken = signAccessToken("0000-0000");

describe("GetUserAttributeVerificationCode target", () => {
  let getUserAttributeVerificationCode: GetUserAttributeVerificationCodeTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({
      Id: "test",
      AutoVerifiedAttributes: ["email"],
    });
    mockMessages = newMockMessages();
    getUserAttributeVerificationCode = GetUserAttributeVerificationCode({
      cognito: newMockCognitoService(mockUserPoolService),
      messages: mockMessages,
      otp: () => "123456",
    });
  });

  it("throws if token isn't valid", async () => {
    await expect(
      getUserAttributeVerificationCode(TestContext, {
        AccessToken: "blah",
        AttributeName: "email",
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      getUserAttributeVerificationCode(TestContext, {
        AccessToken: validToken,
        AttributeName: "email",
      }),
    ).rejects.toEqual(new UserNotFoundError());
  });

  it("throws if the user doesn't have a valid way to contact them", async () => {
    const user = TDB.user({
      Attributes: [],
    });

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      getUserAttributeVerificationCode(TestContext, {
        ClientMetadata: {
          client: "metadata",
        },
        AccessToken: validToken,
        AttributeName: "email",
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        "User has no attribute matching desired auto verified attributes",
      ),
    );
  });

  it("delivers a OTP code to the user", async () => {
    const user = TDB.user({
      Attributes: [attribute("email", "example@example.com")],
    });

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await getUserAttributeVerificationCode(TestContext, {
      ClientMetadata: {
        client: "metadata",
      },
      AccessToken: validToken,
      AttributeName: "email",
    });

    expect(mockMessages.deliver).toHaveBeenCalledWith(
      TestContext,
      "VerifyUserAttribute",
      null,
      "test",
      user,
      "123456",
      { client: "metadata" },
      {
        AttributeName: "email",
        DeliveryMedium: "EMAIL",
        Destination: attributeValue("email", user.Attributes),
      },
    );

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        AttributeVerificationCode: "123456",
      }),
    );
  });
});
