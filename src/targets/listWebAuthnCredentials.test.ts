import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import type { UserPoolService } from "../services";
import {
  ListWebAuthnCredentials,
  type ListWebAuthnCredentialsTarget,
} from "./listWebAuthnCredentials";

describe("ListWebAuthnCredentials target", () => {
  let listWebAuthnCredentials: ListWebAuthnCredentialsTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    listWebAuthnCredentials = ListWebAuthnCredentials({
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("returns the user's credentials without the public-key blob", async () => {
    const user = TDB.user({
      WebAuthnCredentials: [
        {
          CredentialId: "cred-1",
          FriendlyCredentialName: "Passkey",
          RelyingPartyId: "localhost",
          CreatedAt: new Date(),
          PublicKey: "secret-blob",
        },
      ],
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await listWebAuthnCredentials(TestContext, {
      AccessToken: signAccessToken(user.Username),
    });

    expect(result.Credentials).toHaveLength(1);
    expect(result.Credentials[0].CredentialId).toEqual("cred-1");
    expect(result.Credentials[0]).not.toHaveProperty("PublicKey");
  });

  it("returns an empty list when the user has no credentials", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await listWebAuthnCredentials(TestContext, {
      AccessToken: signAccessToken(user.Username),
    });

    expect(result.Credentials).toEqual([]);
  });
});
