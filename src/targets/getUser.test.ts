import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, UserNotFoundError } from "../errors";
import type { UserPoolService } from "../services";
import { attributeValue } from "../services/userPoolService";
import { GetUser, type GetUserTarget } from "./getUser";

describe("GetUser target", () => {
  let getUser: GetUserTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    getUser = GetUser({
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("parses token get user by sub", async () => {
    const user = TDB.user();

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const output = await getUser(TestContext, {
      AccessToken: signAccessToken(
        attributeValue("sub", user.Attributes) ?? "",
      ),
    });

    expect(output).toBeDefined();
    expect(output).toEqual({
      UserAttributes: user.Attributes,
      Username: user.Username,
    });
  });

  it("throws if token isn't valid", async () => {
    await expect(
      getUser(TestContext, {
        AccessToken: "blah",
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      getUser(TestContext, {
        AccessToken: signAccessToken("0000-0000"),
      }),
    ).rejects.toEqual(new UserNotFoundError());
  });
});
