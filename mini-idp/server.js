import express from "express";
import {
  exportJWK,
  exportPKCS8,
  exportSPKI,
  generateKeyPair,
  SignJWT,
} from "jose";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "localhost";
const ISSUER = process.env.ISSUER || `http://${HOST}:${PORT}`;
const DEFAULT_AUDIENCE = process.env.AUDIENCE || "test-api";
const DEFAULT_SCOPE = process.env.SCOPE || "read write";
const DEFAULT_KID = process.env.KID || "key1";
const DEFAULT_EXPIRES_IN = Number(process.env.EXPIRES_IN || 3600);

/** @type {{ kid: string, jwk: any, publicKey: CryptoKey, privateKey: CryptoKey }} */
let activeKey = null;
/** @type {Array<{ kid: string, jwk: any, publicKey: CryptoKey, privateKey: CryptoKey }>} */
let allKeys = [];

function nowEpoch() {
  return Math.floor(Date.now() / 1000);
}

async function makeKey(kid) {
  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    modulusLength: 2048,
  });

  const jwk = await exportJWK(publicKey);
  jwk.kty = "RSA";
  jwk.use = "sig";
  jwk.alg = "RS256";
  jwk.kid = kid;

  return {
    kid,
    jwk,
    publicKey,
    privateKey,
  };
}

async function activateNewKey(kid, keepOld = true) {
  const key = await makeKey(kid);
  activeKey = key;
  allKeys = keepOld ? [key, ...allKeys] : [key];
  return key;
}

function getDiscoveryDocument() {
  return {
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/jwks.json`,
    token_endpoint: `${ISSUER}/token`,
    authorization_endpoint: `${ISSUER}/authorize`,
    response_types_supported: ["token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    grant_types_supported: ["client_credentials", "password", "refresh_token"],
  };
}

app.get("/", (req, res) => {
  res.json({
    name: "mini-idp",
    issuer: ISSUER,
    endpoints: {
      discovery: `${ISSUER}/.well-known/openid-configuration`,
      jwks: `${ISSUER}/jwks.json`,
      token: `${ISSUER}/token`,
      rotate: `${ISSUER}/rotate`,
      keys: `${ISSUER}/keys`,
    },
  });
});

app.get("/.well-known/openid-configuration", (req, res) => {
  res.json(getDiscoveryDocument());
});

app.get("/jwks.json", (req, res) => {
  res.json({ keys: allKeys.map((k) => k.jwk) });
});

app.get("/keys", async (req, res) => {
  const keys = await Promise.all(
    allKeys.map(async (k) => ({
      kid: k.kid,
      publicKeyPem: await exportSPKI(k.publicKey),
      privateKeyPem: await exportPKCS8(k.privateKey),
      jwk: k.jwk,
      active: activeKey?.kid === k.kid,
    }))
  );
  res.json({ issuer: ISSUER, keys });
});

app.get("/authorize", (req, res) => {
  res.status(501).json({
    error: "not_implemented",
    error_description: "This mini IdP only supports JWT minting via POST /token for local testing.",
  });
});

app.post("/token", async (req, res) => {
  try {
    const body = req.body ?? {};
    const sub = body.sub || "test-user";
    const aud = body.aud || DEFAULT_AUDIENCE;
    const scope = body.scope || DEFAULT_SCOPE;
    const expiresIn = Number(body.expires_in || DEFAULT_EXPIRES_IN);
    const kid = body.kid || activeKey.kid;
    const requestedKey = allKeys.find((k) => k.kid === kid);

    if (!requestedKey) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: `Unknown kid '${kid}'. Available kids: ${allKeys.map((k) => k.kid).join(", ")}`,
      });
    }

    const extraClaims =
      body.claims && typeof body.claims === "object" && !Array.isArray(body.claims)
        ? body.claims
        : {};

    const currentTime = nowEpoch();
    const claims = {
      sub,
      iss: ISSUER,
      aud,
      iat: currentTime,
      nbf: currentTime,
      exp: currentTime + expiresIn,
      scope,
      ...extraClaims,
    };

    const accessToken = await new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: requestedKey.kid })
      .sign(requestedKey.privateKey);

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope,
      issued_token_kid: requestedKey.kid,
      issuer: ISSUER,
      claims,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "server_error",
      error_description: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/rotate", async (req, res) => {
  try {
    const kid = req.body?.kid || `key-${Date.now()}`;
    const keepOld = req.body?.keep_old !== false;
    const key = await activateNewKey(kid, keepOld);
    res.json({
      message: "Key rotated",
      active_kid: key.kid,
      all_kids: allKeys.map((k) => k.kid),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "server_error",
      error_description: error instanceof Error ? error.message : String(error),
    });
  }
});

async function start() {
  await activateNewKey(DEFAULT_KID, false);

  app.listen(PORT, async () => {
    const publicPem = await exportSPKI(activeKey.publicKey);
    console.log("mini-idp running");
    console.log(`Issuer:     ${ISSUER}`);
    console.log(`Discovery:  ${ISSUER}/.well-known/openid-configuration`);
    console.log(`JWKS:       ${ISSUER}/jwks.json`);
    console.log(`Token:      ${ISSUER}/token`);
    console.log(`Active kid: ${activeKey.kid}`);
    console.log("\nPublic key:\n");
    console.log(publicPem);
  });
}

start().catch((error) => {
  console.error("Failed to start mini-idp", error);
  process.exit(1);
});
