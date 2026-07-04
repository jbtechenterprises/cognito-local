import { createPrivateKey, createSign } from "node:crypto";
import * as uuid from "uuid";
import PrivateKey from "../keys/cognitoLocal.private.json";

const privateKey = createPrivateKey(PrivateKey.pem);

const base64UrlJson = (value: object): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

/**
 * signAccessToken produces a valid RS256 access token for target unit tests. The
 * `sub`/`client_id`/`username` claims must be present because access-token
 * targets resolve the user by decoding the token.
 *
 * Signing is done synchronously with Node's crypto so call sites don't need to
 * await (jose's signer is async-only). The token is a real RS256 JWT, decodable
 * by jose's decodeJwt.
 */
export const signAccessToken = (sub: string, clientId = "test"): string => {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: "CognitoLocal" };
  const payload = {
    sub,
    event_id: "0",
    token_use: "access",
    scope: "aws.cognito.signin.user.admin",
    auth_time: now,
    jti: uuid.v4(),
    client_id: clientId,
    username: sub,
    iss: "http://localhost:9229/test",
    iat: now,
    exp: now + 24 * 60 * 60,
  };

  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
  const signature = createSign("RSA-SHA256")
    .update(signingInput)
    .sign(privateKey, "base64url");

  return `${signingInput}.${signature}`;
};
