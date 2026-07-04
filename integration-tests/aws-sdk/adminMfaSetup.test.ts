import { describe, expect, it } from "vitest";
import { generate as generateTotp } from "../../src/services/totp";
import { withCognitoSdk } from "./setup";

describe(
  "forced first-login MFA_SETUP enrollment (admin flow)",
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

    it("challenges an unenrolled user with MFA_SETUP via AdminInitiateAuth and enrolls them end-to-end", async () => {
      const { client, userPoolId, clientId } = await createPoolWithForcedMfa();

      // 1. Admin sign in: pool requires MFA and the user has none -> MFA_SETUP.
      const auth = await client
        .adminInitiateAuth({
          UserPoolId: userPoolId,
          ClientId: clientId,
          AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
          AuthParameters: { USERNAME: "abc", PASSWORD: "Password1!" },
        })
        .promise();

      expect(auth.ChallengeName).toEqual("MFA_SETUP");
      expect(auth.Session).toBeDefined();
      expect(auth.ChallengeParameters?.MFAS_CAN_SETUP).toEqual(
        JSON.stringify(["SOFTWARE_TOKEN_MFA"]),
      );

      // 2. Associate + verify the software token using the challenge Session
      //    (these have no admin variant; they run against the Session).
      const associate = await client
        .associateSoftwareToken({ Session: auth.Session })
        .promise();
      const verify = await client
        .verifySoftwareToken({
          Session: associate.Session,
          UserCode: generateTotp(associate.SecretCode!),
        })
        .promise();
      expect(verify.Status).toEqual("SUCCESS");

      // 3. Complete via AdminRespondToAuthChallenge and receive tokens.
      const completed = await client
        .adminRespondToAuthChallenge({
          UserPoolId: userPoolId,
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

    it("re-challenges an enrolled user with SOFTWARE_TOKEN_MFA on next admin sign-in", async () => {
      const { client, userPoolId, clientId } = await createPoolWithForcedMfa();

      const auth = await client
        .adminInitiateAuth({
          UserPoolId: userPoolId,
          ClientId: clientId,
          AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
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
        .adminRespondToAuthChallenge({
          UserPoolId: userPoolId,
          ClientId: clientId,
          ChallengeName: "MFA_SETUP",
          Session: associate.Session,
          ChallengeResponses: { USERNAME: "abc" },
        })
        .promise();

      const secondAuth = await client
        .adminInitiateAuth({
          UserPoolId: userPoolId,
          ClientId: clientId,
          AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
          AuthParameters: { USERNAME: "abc", PASSWORD: "Password1!" },
        })
        .promise();

      expect(secondAuth.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
    });
  }),
);
