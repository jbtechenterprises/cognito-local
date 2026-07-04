import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { UserPoolService } from "../services";
import { attribute } from "../services/userPoolService";
import {
  DeleteUserAttributes,
  type DeleteUserAttributesTarget,
} from "./deleteUserAttributes";

const clock = new ClockFake(new Date());

const validToken = signAccessToken("0000-0000");

describe("DeleteUserAttributes target", () => {
  let deleteUserAttributes: DeleteUserAttributesTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    deleteUserAttributes = DeleteUserAttributes({
      clock,
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("throws if the user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      deleteUserAttributes(TestContext, {
        AccessToken: validToken,
        UserAttributeNames: ["custom:example"],
      }),
    ).rejects.toEqual(new NotAuthorizedError());
  });

  it("throws if the token is invalid", async () => {
    await expect(
      deleteUserAttributes(TestContext, {
        AccessToken: "invalid token",
        UserAttributeNames: ["custom:example"],
      }),
    ).rejects.toEqual(new InvalidParameterError());
  });

  it("saves the updated attributes on the user", async () => {
    const user = TDB.user({
      Attributes: [
        attribute("email", "example@example.com"),
        attribute("custom:example", "1"),
      ],
    });

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await deleteUserAttributes(TestContext, {
      AccessToken: validToken,
      UserAttributeNames: ["custom:example"],
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
      ...user,
      Attributes: [attribute("email", "example@example.com")],
      UserLastModifiedDate: clock.get(),
    });
  });
});
