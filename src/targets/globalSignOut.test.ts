import type { GlobalSignOutRequest } from "aws-sdk/clients/cognitoidentityserviceprovider";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { UserPoolService } from "../services";
import { GlobalSignOut, type GlobalSignOutTarget } from "./globalSignOut";

describe("GlobalSignOut target", () => {
  let globalSignOut: GlobalSignOutTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    globalSignOut = GlobalSignOut({
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("clears every refresh token for the user", async () => {
    const user = TDB.user({ RefreshTokens: ["one", "two"] });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await globalSignOut(TestContext, {
      AccessToken: signAccessToken(user.Username),
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({ RefreshTokens: [] }),
    );
  });

  it("throws when AccessToken is missing", async () => {
    await expect(
      globalSignOut(TestContext, {} as GlobalSignOutRequest),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("throws when the user does not exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      globalSignOut(TestContext, { AccessToken: signAccessToken("nobody") }),
    ).rejects.toBeInstanceOf(NotAuthorizedError);
  });
});
