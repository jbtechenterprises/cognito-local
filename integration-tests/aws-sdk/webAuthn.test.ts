import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

/**
 * WebAuthn operations are absent from the bundled aws-sdk v2, so the SDK client
 * cannot call them. These tests drive the SDK only for pool/user setup + sign-in,
 * then exercise the WebAuthn targets over raw HTTP with the x-amz-target header
 * (the same wire protocol a newer SDK would use).
 */
describe(
  "WebAuthn (passkey) targets",
  withCognitoSdk((Cognito, { serverUrl }) => {
    const call = async (target: string, body: unknown) => {
      const res = await fetch(`${serverUrl()}/`, {
        method: "POST",
        headers: {
          "content-type": "application/x-amz-json-1.1",
          "x-amz-target": `AWSCognitoIdentityProviderService.${target}`,
        },
        body: JSON.stringify(body),
      });
      const text = await res.text();
      return { status: res.status, body: text ? JSON.parse(text) : {} };
    };

    const signIn = async () => {
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

      return {
        accessToken: auth.AuthenticationResult?.AccessToken!,
        clientId,
        userPoolId,
      };
    };

    it("registers, lists, and deletes a passkey end-to-end", async () => {
      const { accessToken } = await signIn();

      const start = await call("StartWebAuthnRegistration", {
        AccessToken: accessToken,
      });
      expect(start.status).toEqual(200);
      expect(start.body.CredentialCreationOptions?.challenge).toBeDefined();

      const complete = await call("CompleteWebAuthnRegistration", {
        AccessToken: accessToken,
        Credential: { id: "cred-abc", friendlyName: "Test Passkey" },
      });
      expect(complete.status).toEqual(200);

      const listed = await call("ListWebAuthnCredentials", {
        AccessToken: accessToken,
      });
      expect(listed.status).toEqual(200);
      expect(listed.body.Credentials).toHaveLength(1);
      expect(listed.body.Credentials[0].CredentialId).toEqual("cred-abc");

      const deleted = await call("DeleteWebAuthnCredential", {
        AccessToken: accessToken,
        CredentialId: "cred-abc",
      });
      expect(deleted.status).toEqual(200);

      const listedAfter = await call("ListWebAuthnCredentials", {
        AccessToken: accessToken,
      });
      expect(listedAfter.body.Credentials).toHaveLength(0);
    });

    it("completes a WEB_AUTHN challenge for a user with a registered passkey", async () => {
      const { accessToken, clientId } = await signIn();
      await call("CompleteWebAuthnRegistration", {
        AccessToken: accessToken,
        Credential: { id: "cred-1" },
      });

      const responded = await call("RespondToAuthChallenge", {
        ClientId: clientId,
        ChallengeName: "WEB_AUTHN",
        Session: "any-session",
        ChallengeResponses: { USERNAME: "abc" },
      });

      // The user has a registered credential, so the assertion is accepted.
      expect(responded.status).toEqual(200);
      expect(responded.body.AuthenticationResult?.AccessToken).toBeDefined();
    });
  }),
);
