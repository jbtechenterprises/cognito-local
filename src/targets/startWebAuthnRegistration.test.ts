import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { signAccessToken } from "../__tests__/signAccessToken";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError } from "../errors";
import type { UserPoolService } from "../services";
import {
  StartWebAuthnRegistration,
  type StartWebAuthnRegistrationTarget,
} from "./startWebAuthnRegistration";

describe("StartWebAuthnRegistration target", () => {
  let startWebAuthnRegistration: StartWebAuthnRegistrationTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    startWebAuthnRegistration = StartWebAuthnRegistration({
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("returns CredentialCreationOptions with a challenge", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await startWebAuthnRegistration(TestContext, {
      AccessToken: signAccessToken(user.Username),
    });

    const options = result.CredentialCreationOptions as Record<string, unknown>;
    expect(typeof options.challenge).toEqual("string");
    expect(options.rp).toBeDefined();
    expect(options.user).toBeDefined();
    expect(options.pubKeyCredParams).toBeDefined();
  });

  it("throws when AccessToken is missing", async () => {
    await expect(
      startWebAuthnRegistration(TestContext, { AccessToken: "" }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });
});
