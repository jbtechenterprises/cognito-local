import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import type { UserPoolService } from "../services";
import {
  CompleteWebAuthnRegistration,
  type CompleteWebAuthnRegistrationTarget,
} from "./completeWebAuthnRegistration";

describe("CompleteWebAuthnRegistration target", () => {
  let completeWebAuthnRegistration: CompleteWebAuthnRegistrationTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    completeWebAuthnRegistration = CompleteWebAuthnRegistration({
      clock: new ClockFake(new Date()),
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("stores the credential on the user, preferring its id", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await completeWebAuthnRegistration(TestContext, {
      AccessToken: signAccessToken(user.Username),
      Credential: { id: "cred-123", friendlyName: "My Passkey" },
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        WebAuthnCredentials: [
          expect.objectContaining({
            CredentialId: "cred-123",
            FriendlyCredentialName: "My Passkey",
          }),
        ],
      }),
    );
  });

  it("appends to existing credentials", async () => {
    const user = TDB.user({
      WebAuthnCredentials: [
        { CredentialId: "existing", CreatedAt: new Date() },
      ],
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await completeWebAuthnRegistration(TestContext, {
      AccessToken: signAccessToken(user.Username),
      Credential: { id: "new-cred" },
    });

    const saved = mockUserPoolService.saveUser.mock.calls[0][1];
    expect(saved.WebAuthnCredentials).toHaveLength(2);
    expect(saved.WebAuthnCredentials?.[1].CredentialId).toEqual("new-cred");
  });

  it("generates a credential id when the client omits one", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await completeWebAuthnRegistration(TestContext, {
      AccessToken: signAccessToken(user.Username),
      Credential: {},
    });

    const saved = mockUserPoolService.saveUser.mock.calls[0][1];
    expect(saved.WebAuthnCredentials?.[0].CredentialId).toMatch(/.+/);
  });
});
