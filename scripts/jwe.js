import { CipherSuite } from "hpke";
import { algorithms } from "./algorithms.js";

import { createCipheriv, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const jwksDir = join(process.cwd(), "examples", "jwks");
const outDir = join(process.cwd(), "examples", "jwe");
const examplesDir = join(process.cwd(), "examples");
mkdirSync(outDir, { recursive: true });

const encoder = new TextEncoder();

const plaintext =
  "You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

const aadString = "The Fellowship of the Ring";

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function base64urlDecode(str) {
  return new Uint8Array(Buffer.from(str, "base64url"));
}

function serializePublicKey(jwk) {
  if (jwk.kty === "EC") {
    return new Uint8Array([
      0x04,
      ...base64urlDecode(jwk.x),
      ...base64urlDecode(jwk.y),
    ]);
  }
  if (jwk.kty === "OKP") {
    return base64urlDecode(jwk.x);
  }
  throw new Error(`Unsupported JWK kty: ${jwk.kty}`);
}

function recipientStructure(contentEncAlg) {
  const prefix = encoder.encode("JOSE-HPKE rcpt");
  const separator = new Uint8Array([0xff]);
  const algBytes = encoder.encode(contentEncAlg);
  const result = new Uint8Array(prefix.length + 1 + algBytes.length + 1);
  result.set(prefix, 0);
  result.set(separator, prefix.length);
  result.set(algBytes, prefix.length + 1);
  result.set(separator, prefix.length + 1 + algBytes.length);
  return result;
}

function contentEncryption(suite) {
  if (suite.AEAD.id === 0x0001) {
    return { enc: "A128GCM", cekSize: 16, cipherName: "aes-128-gcm" };
  }
  return { enc: "A256GCM", cekSize: 32, cipherName: "aes-256-gcm" };
}

function encryptContent(cipherName, cek, plaintext, aad) {
  const iv = randomBytes(12);
  const cipher = createCipheriv(cipherName, cek, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return { iv, ciphertext, tag: cipher.getAuthTag() };
}

const vectors = [];

for (const { alg, kem, kdf, aead } of algorithms) {
  const isKeyEncryption = alg.endsWith("-KE");
  const jwk = JSON.parse(readFileSync(join(jwksDir, `${alg}.json`), "utf8"));
  const suite = new CipherSuite(kem, kdf, aead);
  const publicKey = await suite.DeserializePublicKey(serializePublicKey(jwk));

  let flattenedJwe;
  let compactJwe;

  if (isKeyEncryption) {
    const { enc, cekSize, cipherName } = contentEncryption(suite);
    const cek = randomBytes(cekSize);
    const info = recipientStructure(enc);

    {
      const { encapsulatedSecret, ciphertext: encryptedKey } = await suite.Seal(
        publicKey,
        cek,
        { info },
      );
      const protectedHeader = {
        alg,
        kid: jwk.kid,
        enc,
        ek: base64url(encapsulatedSecret),
      };
      const protectedHeaderB64 = base64url(encoder.encode(JSON.stringify(protectedHeader)));
      const aadB64 = base64url(encoder.encode(aadString));
      const contentAad = encoder.encode(`${protectedHeaderB64}.${aadB64}`);
      const {
        iv,
        ciphertext: contentCiphertext,
        tag,
      } = encryptContent(cipherName, cek, plaintext, contentAad);

      flattenedJwe = {
        protected: protectedHeaderB64,
        aad: aadB64,
        iv: base64url(iv),
        ciphertext: base64url(contentCiphertext),
        tag: base64url(tag),
        encrypted_key: base64url(encryptedKey),
      };
      writeFileSync(
        join(outDir, `${alg}-flattened.json`),
        JSON.stringify(flattenedJwe, null, 2) + "\n",
      );
    }

    {
      const {
        encapsulatedSecret,
        ciphertext: encryptedKey,
      } = await suite.Seal(publicKey, cek, { info });
      const protectedHeader = {
        alg,
        kid: jwk.kid,
        enc,
        ek: base64url(encapsulatedSecret),
      };
      const protectedHeaderB64 = base64url(encoder.encode(JSON.stringify(protectedHeader)));
      const contentAad = encoder.encode(protectedHeaderB64);
      const {
        iv,
        ciphertext: contentCiphertext,
        tag,
      } = encryptContent(cipherName, cek, plaintext, contentAad);

      compactJwe = [
        protectedHeaderB64,
        base64url(encryptedKey),
        base64url(iv),
        base64url(contentCiphertext),
        base64url(tag),
      ].join(".");
      writeFileSync(join(outDir, `${alg}-compact.txt`), compactJwe + "\n");
    }
  } else {
    {
      const protectedHeader = { alg, kid: jwk.kid };
      const protectedHeaderB64 = base64url(encoder.encode(JSON.stringify(protectedHeader)));
      const aadB64 = base64url(encoder.encode(aadString));
      const hpkeAad = encoder.encode(`${protectedHeaderB64}.${aadB64}`);
      const { encapsulatedSecret, ciphertext } = await suite.Seal(
        publicKey,
        encoder.encode(plaintext),
        { aad: hpkeAad },
      );

      flattenedJwe = {
        protected: protectedHeaderB64,
        aad: aadB64,
        encrypted_key: base64url(encapsulatedSecret),
        ciphertext: base64url(ciphertext),
      };
      writeFileSync(
        join(outDir, `${alg}-flattened.json`),
        JSON.stringify(flattenedJwe, null, 2) + "\n",
      );
    }

    {
      const protectedHeader = { alg, kid: jwk.kid };
      const protectedHeaderB64 = base64url(encoder.encode(JSON.stringify(protectedHeader)));
      const hpkeAad = encoder.encode(protectedHeaderB64);
      const { encapsulatedSecret, ciphertext } = await suite.Seal(
        publicKey,
        encoder.encode(plaintext),
        { aad: hpkeAad },
      );

      compactJwe = [
        protectedHeaderB64,
        base64url(encapsulatedSecret),
        "",
        base64url(ciphertext),
        "",
      ].join(".");
      writeFileSync(join(outDir, `${alg}-compact.txt`), compactJwe + "\n");
    }
  }

  vectors.push({ alg, jwk, flattened: flattenedJwe, compact: compactJwe });
}

writeFileSync(
  join(examplesDir, "jose-vectors.json"),
  JSON.stringify(vectors, null, 2) + "\n",
);
