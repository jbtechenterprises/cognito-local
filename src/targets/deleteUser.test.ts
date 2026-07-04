import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { UserPoolService } from "../services";
import { DeleteUser, type DeleteUserTarget } from "./deleteUser";

describe("DeleteUser target", () => {
  let deleteUser: DeleteUserTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    deleteUser = DeleteUser({
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("parses token get user by sub", async () => {
    const user = TDB.user();

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await deleteUser(TestContext, {
      AccessToken: signAccessToken("0000-0000"),
    });

    expect(mockUserPoolService.deleteUser).toHaveBeenCalledWith(
      TestContext,
      user,
    );
  });

  it("throws if token isn't valid", async () => {
    await expect(
      deleteUser(TestContext, {
        AccessToken: "blah",
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      deleteUser(TestContext, {
        AccessToken: signAccessToken("0000-0000"),
      }),
    ).rejects.toEqual(new NotAuthorizedError());
  });
});
