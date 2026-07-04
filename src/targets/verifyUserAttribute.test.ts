import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
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
import { attribute, attributesAppend } from "../services/userPoolService";
import {
  VerifyUserAttribute,
  type VerifyUserAttributeTarget,
} from "./verifyUserAttribute";

const clock = new ClockFake(new Date());

const validToken = signAccessToken("0000-0000");

describe("VerifyUserAttribute target", () => {
  let verifyUserAttribute: VerifyUserAttributeTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    verifyUserAttribute = VerifyUserAttribute({
      clock,
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it.each(["email", "phone_number"] as const)(
    "verifies the user's %s",
    async (attr) => {
      const user = TDB.user({
        Attributes: [
          {
            Name: attr,
            Value: "new value",
          },
          {
            Name: `${attr}_verified`,
            Value: "false",
          },
        ],
        AttributeVerificationCode: "123456",
      });

      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      await verifyUserAttribute(TestContext, {
        AccessToken: validToken,
        AttributeName: attr,
        Code: "123456",
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
        ...user,
        Attributes: attributesAppend(
          user.Attributes,
          attribute(`${attr}_verified`, "true"),
        ),
        UserLastModifiedDate: clock.get(),
        AttributeVerificationCode: undefined,
      });
    },
  );

  it.each(["email", "phone_number"] as const)(
    "verifies and applies the user's %s when it's not been applied yet due to AttributesRequireVerificationBeforeUpdate",
    async (attr) => {
      const user = TDB.user({
        Attributes: [
          {
            Name: attr,
            Value: "original value",
          },
          {
            Name: `${attr}_verified`,
            Value: "true",
          },
        ],
        UnverifiedAttributeChanges: [
          {
            Name: attr,
            Value: "new value",
          },
          {
            Name: `${attr}_verified`,
            Value: "false",
          },
        ],
        AttributeVerificationCode: "123456",
      });

      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      await verifyUserAttribute(TestContext, {
        AccessToken: validToken,
        AttributeName: attr,
        Code: "123456",
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
        ...user,
        Attributes: [
          attribute(attr, "new value"),
          attribute(`${attr}_verified`, "true"),
        ],
        UnverifiedAttributeChanges: undefined,
        UserLastModifiedDate: clock.get(),
        AttributeVerificationCode: undefined,
      });
    },
  );

  it("does nothing for other attributes", async () => {
    const user = TDB.user({
      AttributeVerificationCode: "123456",
    });

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await verifyUserAttribute(TestContext, {
      AccessToken: validToken,
      AttributeName: "something else",
      Code: "123456",
    });

    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });

  it("throws if token isn't valid", async () => {
    await expect(
      verifyUserAttribute(TestContext, {
        AccessToken: "blah",
        AttributeName: "email",
        Code: "123456",
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      verifyUserAttribute(TestContext, {
        AccessToken: validToken,
        AttributeName: "email",
        Code: "123456",
      }),
    ).rejects.toEqual(new NotAuthorizedError());
  });

  it("throws if code doesn't match the user's AttributeVerificationCode", async () => {
    const user = TDB.user({
      AttributeVerificationCode: "5555",
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      verifyUserAttribute(TestContext, {
        AccessToken: validToken,
        AttributeName: "email",
        Code: "123456",
      }),
    ).rejects.toEqual(new CodeMismatchError());
  });
});
