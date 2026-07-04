import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

describe(
  "global sign-out",
  withCognitoSdk((Cognito) => {
    const createUserAndSignIn = async () => {
      const client = Cognito();

      const pool = await client.createUserPool({ PoolName: "test" }).promise();
      const userPoolId = pool.UserPool?.Id!;
      const upc = await client
        .createUserPoolClient({ UserPoolId: userPoolId, ClientName: "test" })
        .promise();
      const clientId = upc.UserPoolClient?.ClientId!;

      await client
        .adminCreateUser({
          DesiredDeliveryMediums: ["EMAIL"],
          TemporaryPassword: "def",
          UserAttributes: [{ Name: "email", Value: "example@example.com" }],
          Username: "abc",
          UserPoolId: userPoolId,
        })
        .promise();
      await client
        .adminSetUserPassword({
          Password: "Password1!",
          Permanent: true,
          Username: "abc",
          UserPoolId: userPoolId,
        })
        .promise();

      const auth = await client
        .initiateAuth({
          ClientId: clientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: { USERNAME: "abc", PASSWORD: "Password1!" },
        })
        .promise();

      return { client, userPoolId, clientId, auth };
    };

    it("GlobalSignOut invalidates the user's refresh tokens", async () => {
      const { client, clientId, auth } = await createUserAndSignIn();
      const refreshToken = auth.AuthenticationResult?.RefreshToken!;

      await client
        .globalSignOut({ AccessToken: auth.AuthenticationResult?.AccessToken! })
        .promise();

      await expect(
        client
          .initiateAuth({
            ClientId: clientId,
            AuthFlow: "REFRESH_TOKEN_AUTH",
            AuthParameters: { REFRESH_TOKEN: refreshToken },
          })
          .promise(),
      ).rejects.toMatchObject({ code: "NotAuthorizedException" });
    });

    it("AdminUserGlobalSignOut invalidates the user's refresh tokens", async () => {
      const { client, userPoolId, clientId, auth } =
        await createUserAndSignIn();
      const refreshToken = auth.AuthenticationResult?.RefreshToken!;

      await client
        .adminUserGlobalSignOut({ UserPoolId: userPoolId, Username: "abc" })
        .promise();

      await expect(
        client
          .initiateAuth({
            ClientId: clientId,
            AuthFlow: "REFRESH_TOKEN_AUTH",
            AuthParameters: { REFRESH_TOKEN: refreshToken },
          })
          .promise(),
      ).rejects.toMatchObject({ code: "NotAuthorizedException" });
    });
  }),
);
