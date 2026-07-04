import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import { InvalidParameterError, ResourceNotFoundError } from "../errors";
import type { CognitoService, UserPoolService } from "../services";
import {
  CreateResourceServer,
  type CreateResourceServerTarget,
} from "./createResourceServer";

describe("CreateResourceServer target", () => {
  let createResourceServer: CreateResourceServerTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockCognitoService: MockedObject<CognitoService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    mockCognitoService = newMockCognitoService(mockUserPoolService);

    createResourceServer = CreateResourceServer({
      cognito: mockCognitoService,
    });
  });

  it("creates and returns a resource server", async () => {
    const result = await createResourceServer(TestContext, {
      Identifier: "https://my-api.example.com",
      Name: "My API",
      Scopes: [{ ScopeName: "read", ScopeDescription: "Read access" }],
      UserPoolId: "test",
    });

    expect(mockUserPoolService.saveResourceServer).toHaveBeenCalledWith(
      TestContext,
      {
        Identifier: "https://my-api.example.com",
        Name: "My API",
        Scopes: [{ ScopeName: "read", ScopeDescription: "Read access" }],
      },
    );

    expect(result).toEqual({
      ResourceServer: {
        Identifier: "https://my-api.example.com",
        Name: "My API",
        Scopes: [{ ScopeName: "read", ScopeDescription: "Read access" }],
        UserPoolId: "test",
      },
    });
  });

  it("creates a resource server without scopes", async () => {
    const result = await createResourceServer(TestContext, {
      Identifier: "https://my-api.example.com",
      Name: "My API",
      UserPoolId: "test",
    });

    expect(mockUserPoolService.saveResourceServer).toHaveBeenCalledWith(
      TestContext,
      {
        Identifier: "https://my-api.example.com",
        Name: "My API",
        Scopes: undefined,
      },
    );

    expect(result).toEqual({
      ResourceServer: {
        Identifier: "https://my-api.example.com",
        Name: "My API",
        Scopes: undefined,
        UserPoolId: "test",
      },
    });
  });

  it("throws if the Identifier is missing", async () => {
    await expect(
      createResourceServer(TestContext, {
        Identifier: "",
        Name: "My API",
        UserPoolId: "test",
      }),
    ).rejects.toEqual(
      new InvalidParameterError("Missing required parameter Identifier"),
    );

    expect(mockUserPoolService.saveResourceServer).not.toHaveBeenCalled();
  });

  it("throws if the Name is missing", async () => {
    await expect(
      createResourceServer(TestContext, {
        Identifier: "https://my-api.example.com",
        Name: "",
        UserPoolId: "test",
      }),
    ).rejects.toEqual(
      new InvalidParameterError("Missing required parameter Name"),
    );

    expect(mockUserPoolService.saveResourceServer).not.toHaveBeenCalled();
  });

  it("throws if the user pool doesn't exist", async () => {
    mockCognitoService.getUserPool.mockRejectedValue(
      new ResourceNotFoundError("User Pool missing not found"),
    );

    await expect(
      createResourceServer(TestContext, {
        Identifier: "https://my-api.example.com",
        Name: "My API",
        UserPoolId: "missing",
      }),
    ).rejects.toEqual(new ResourceNotFoundError("User Pool missing not found"));

    expect(mockUserPoolService.saveResourceServer).not.toHaveBeenCalled();
  });
});
