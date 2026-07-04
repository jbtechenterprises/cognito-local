import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  InvalidParameterError,
  InvalidPasswordError,
  NotAuthorizedError,
} from "../errors";
import type { UserPoolService } from "../services";
import { ChangePassword, type ChangePasswordTarget } from "./changePassword";

const currentDate = new Date();

describe("ChangePassword target", () => {
  let changePassword: ChangePasswordTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    changePassword = ChangePassword({
      cognito: newMockCognitoService(mockUserPoolService),
      clock: new ClockFake(currentDate),
    });
  });

  it("throws if token isn't valid", async () => {
    await expect(
      changePassword(TestContext, {
        AccessToken: "blah",
        PreviousPassword: "abc",
        ProposedPassword: "def",
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);

    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      changePassword(TestContext, {
        AccessToken: signAccessToken("0000-0000"),
        PreviousPassword: "abc",
        ProposedPassword: "def",
      }),
    ).rejects.toEqual(new NotAuthorizedError());

    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });

  it("throws if previous password doesn't match", async () => {
    const user = TDB.user({
      Password: "previous-password",
    });

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      changePassword(TestContext, {
        AccessToken: signAccessToken("0000-0000"),
        PreviousPassword: "abc",
        ProposedPassword: "def",
      }),
    ).rejects.toEqual(new InvalidPasswordError());

    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });

  it("updates the user's password if the previous password matches", async () => {
    const user = TDB.user({
      Password: "previous-password",
    });

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await changePassword(TestContext, {
      AccessToken: signAccessToken("0000-0000"),
      PreviousPassword: "previous-password",
      ProposedPassword: "new-password",
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
      ...user,
      Password: "new-password",
      UserLastModifiedDate: currentDate,
    });
  });
});
