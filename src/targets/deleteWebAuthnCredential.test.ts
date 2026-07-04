import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError } from "../errors";
import type { UserPoolService } from "../services";
import {
  DeleteWebAuthnCredential,
  type DeleteWebAuthnCredentialTarget,
} from "./deleteWebAuthnCredential";

describe("DeleteWebAuthnCredential target", () => {
  let deleteWebAuthnCredential: DeleteWebAuthnCredentialTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    deleteWebAuthnCredential = DeleteWebAuthnCredential({
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("removes the matching credential and leaves the rest", async () => {
    const user = TDB.user({
      WebAuthnCredentials: [
        { CredentialId: "keep", CreatedAt: new Date() },
        { CredentialId: "remove", CreatedAt: new Date() },
      ],
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await deleteWebAuthnCredential(TestContext, {
      AccessToken: signAccessToken(user.Username),
      CredentialId: "remove",
    });

    const saved = mockUserPoolService.saveUser.mock.calls[0][1];
    expect(saved.WebAuthnCredentials).toEqual([
      expect.objectContaining({ CredentialId: "keep" }),
    ]);
  });

  it("throws when CredentialId is missing", async () => {
    await expect(
      deleteWebAuthnCredential(TestContext, {
        AccessToken: signAccessToken("abc"),
        CredentialId: "",
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });
});
