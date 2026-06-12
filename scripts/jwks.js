import { CipherSuite } from "hpke";
import { algorithms } from "./algorithms.js";

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const outDir = join(process.cwd(), "examples", "jwks");
mkdirSync(outDir, { recursive: true });

const encoder = new TextEncoder();

const kemParams = new Map([
  [0x0010, { kty: "EC", crv: "P-256", coordinateSize: 32 }],
  [0x0011, { kty: "EC", crv: "P-384", coordinateSize: 48 }],
  [0x0012, { kty: "EC", crv: "P-521", coordinateSize: 66 }],
  [0x0020, { kty: "OKP", crv: "X25519" }],
  [0x0021, { kty: "OKP", crv: "X448" }],
]);

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function jwkThumbprint(jwk) {
  const input = jwk.kty === "EC"
    ? JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
    : JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return createHash("sha256").update(input).digest("base64url");
}

function deriveIkm(suite, alg) {
  const ikm = new Uint8Array(suite.KEM.Nsk);
  const algBytes = encoder.encode(alg);
  const ids = new Uint8Array(6);
  new DataView(ids.buffer).setUint16(0, suite.KEM.id);
  new DataView(ids.buffer).setUint16(2, suite.KDF.id);
  new DataView(ids.buffer).setUint16(4, suite.AEAD.id);
  const label = encoder.encode("JOSE-HPKE");
  const suffix = new Uint8Array(label.length + ids.length + algBytes.length);
  suffix.set(label, 0);
  suffix.set(ids, label.length);
  suffix.set(algBytes, label.length + ids.length);
  ikm.set(suffix, ikm.length - suffix.length);
  return ikm;
}

function buildJwk(alg, suite, serializedPublicKey, serializedPrivateKey) {
  const params = kemParams.get(suite.KEM.id);
  if (!params) {
    throw new Error(`Unsupported KEM id: ${suite.KEM.id}`);
  }

  let jwk;
  if (params.kty === "EC") {
    if (serializedPublicKey[0] !== 0x04) {
      throw new Error(`Unexpected EC public key encoding for ${alg}`);
    }
    const x = serializedPublicKey.subarray(1, 1 + params.coordinateSize);
    const y = serializedPublicKey.subarray(1 + params.coordinateSize);
    jwk = {
      kty: params.kty,
      crv: params.crv,
      x: base64url(x),
      y: base64url(y),
      d: base64url(serializedPrivateKey),
      alg,
      use: "enc",
    };
  } else {
    jwk = {
      kty: params.kty,
      crv: params.crv,
      x: base64url(serializedPublicKey),
      d: base64url(serializedPrivateKey),
      alg,
      use: "enc",
    };
  }

  return { ...jwk, kid: jwkThumbprint(jwk) };
}

for (const { alg, kem, kdf, aead } of algorithms) {
  const suite = new CipherSuite(kem, kdf, aead);
  const keyPair = await suite.DeriveKeyPair(deriveIkm(suite, alg), true);
  const publicKey = new Uint8Array(await suite.SerializePublicKey(keyPair.publicKey));
  const privateKey = new Uint8Array(await suite.SerializePrivateKey(keyPair.privateKey));
  const jwk = buildJwk(alg, suite, publicKey, privateKey);
  writeFileSync(join(outDir, `${alg}.json`), JSON.stringify(jwk, null, 2) + "\n");
}
