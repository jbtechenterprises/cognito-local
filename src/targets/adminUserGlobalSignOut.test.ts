import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { UserNotFoundError } from "../errors";
import type { UserPoolService } from "../services";
import {
  AdminUserGlobalSignOut,
  type AdminUserGlobalSignOutTarget,
} from "./adminUserGlobalSignOut";

describe("AdminUserGlobalSignOut target", () => {
  let adminUserGlobalSignOut: AdminUserGlobalSignOutTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    adminUserGlobalSignOut = AdminUserGlobalSignOut({
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("clears every refresh token for the user", async () => {
    const user = TDB.user({ RefreshTokens: ["one", "two"] });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await adminUserGlobalSignOut(TestContext, {
      UserPoolId: "test",
      Username: user.Username,
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({ RefreshTokens: [] }),
    );
  });

  it("throws when the user does not exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      adminUserGlobalSignOut(TestContext, {
        UserPoolId: "test",
        Username: "nobody",
      }),
    ).rejects.toBeInstanceOf(UserNotFoundError);
  });
});
