import { describe, expect, it } from "vitest";
import { generate as generateTotp } from "../../src/services/totp";
import { withCognitoSdk } from "./setup";

describe(
  "forced first-login MFA_SETUP enrollment",
  withCognitoSdk((Cognito) => {
    const createPoolWithForcedMfa = async () => {
      const client = Cognito();

      const pool = await client.createUserPool({ PoolName: "test" }).promise();
      const userPoolId = pool.UserPool?.Id!;

      const upc = await client
        .createUserPoolClient({ UserPoolId: userPoolId, ClientName: "test" })
        .promise();
      const clientId = upc.UserPoolClient?.ClientId!;

      await client
        .setUserPoolMfaConfig({
          UserPoolId: userPoolId,
          MfaConfiguration: "ON",
          SoftwareTokenMfaConfiguration: { Enabled: true },
        })
        .promise();

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

      return { client, userPoolId, clientId };
    };

    it("challenges an unenrolled user with MFA_SETUP and enrolls them end-to-end", async () => {
      const { client, clientId } = await createPoolWithForcedMfa();

      // 1. Sign in: pool requires MFA and the user has none -> MFA_SETUP.
      const auth = await client
        .initiateAuth({
          ClientId: clientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: { USERNAME: "abc", PASSWORD: "Password1!" },
        })
        .promise();

      expect(auth.ChallengeName).toEqual("MFA_SETUP");
      expect(auth.Session).toBeDefined();
      expect(auth.ChallengeParameters?.MFAS_CAN_SETUP).toEqual(
        JSON.stringify(["SOFTWARE_TOKEN_MFA"]),
      );

      // 2. Associate a software token using the challenge Session.
      const associate = await client
        .associateSoftwareToken({ Session: auth.Session })
        .promise();

      expect(associate.SecretCode).toMatch(/^[A-Z2-7]+=*$/);
      expect(associate.Session).toBeDefined();

      // 3. Verify the software token with a valid TOTP code.
      const verify = await client
        .verifySoftwareToken({
          Session: associate.Session,
          UserCode: generateTotp(associate.SecretCode!),
        })
        .promise();

      expect(verify.Status).toEqual("SUCCESS");
      expect(verify.Session).toBeDefined();

      // 4. Complete the challenge and receive tokens.
      const completed = await client
        .respondToAuthChallenge({
          ClientId: clientId,
          ChallengeName: "MFA_SETUP",
          Session: verify.Session,
          ChallengeResponses: { USERNAME: "abc" },
        })
        .promise();

      expect(completed.AuthenticationResult?.AccessToken).toBeDefined();
      expect(completed.AuthenticationResult?.IdToken).toBeDefined();
      expect(completed.AuthenticationResult?.RefreshToken).toBeDefined();
    });

    it("requires the software token to be verified before completing", async () => {
      const { client, clientId } = await createPoolWithForcedMfa();

      const auth = await client
        .initiateAuth({
          ClientId: clientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: { USERNAME: "abc", PASSWORD: "Password1!" },
        })
        .promise();

      await client.associateSoftwareToken({ Session: auth.Session }).promise();

      // Skip verifySoftwareToken -> the session is not verified.
      await expect(
        client
          .respondToAuthChallenge({
            ClientId: clientId,
            ChallengeName: "MFA_SETUP",
            Session: auth.Session,
            ChallengeResponses: { USERNAME: "abc" },
          })
          .promise(),
      ).rejects.toMatchObject({ code: "InvalidParameterException" });
    });

    it("re-challenges an enrolled user with SOFTWARE_TOKEN_MFA on next sign-in", async () => {
      const { client, clientId } = await createPoolWithForcedMfa();

      // Enroll.
      const auth = await client
        .initiateAuth({
          ClientId: clientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: { USERNAME: "abc", PASSWORD: "Password1!" },
        })
        .promise();
      const associate = await client
        .associateSoftwareToken({ Session: auth.Session })
        .promise();
      await client
        .verifySoftwareToken({
          Session: associate.Session,
          UserCode: generateTotp(associate.SecretCode!),
        })
        .promise();
      await client
        .respondToAuthChallenge({
          ClientId: clientId,
          ChallengeName: "MFA_SETUP",
          Session: associate.Session,
          ChallengeResponses: { USERNAME: "abc" },
        })
        .promise();

      // Sign in again: now the user has SOFTWARE_TOKEN_MFA enrolled.
      const secondAuth = await client
        .initiateAuth({
          ClientId: clientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: { USERNAME: "abc", PASSWORD: "Password1!" },
        })
        .promise();

      expect(secondAuth.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
    });
  }),
);
