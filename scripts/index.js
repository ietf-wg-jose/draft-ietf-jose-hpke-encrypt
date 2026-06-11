import { algorithms } from "./algorithms.js";
import testVectorSection from "./test-vector-section.js";

import {
  existsSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const draftPath = join(process.cwd(), "draft-ietf-jose-hpke-encrypt.md");
const algorithmsPath = join(__dirname, "algorithms.js");
const hashPath = join(__dirname, ".algorithms-hash");
const jwksDir = join(process.cwd(), "examples", "jwks");
const jweDir = join(process.cwd(), "examples", "jwe");
const vectorsPath = join(process.cwd(), "examples", "jose-vectors.json");
const force = process.argv.includes("--force");

const algorithmsHash = createHash("sha256")
  .update(readFileSync(algorithmsPath))
  .digest("hex");
const previousHash = existsSync(hashPath)
  ? readFileSync(hashPath, "utf8").trim()
  : null;

if (
  !force &&
  previousHash === algorithmsHash &&
  existsSync(jwksDir) &&
  existsSync(jweDir) &&
  existsSync(vectorsPath)
) {
  console.log("Examples up to date, skipping regeneration.");
} else {
  rmSync(jwksDir, { recursive: true, force: true });
  rmSync(jweDir, { recursive: true, force: true });
  rmSync(vectorsPath, { force: true });
  execFileSync(process.execPath, ["--no-warnings", join(__dirname, "jwks.js")], {
    stdio: "inherit",
  });
  execFileSync(process.execPath, ["--no-warnings", join(__dirname, "jwe.js")], {
    stdio: "inherit",
  });
  writeFileSync(hashPath, algorithmsHash + "\n");
}

let draft = readFileSync(draftPath, "utf8");

function replaceSection(name, content) {
  const beginMarker = `<!-- begin:${name} ; see README for regeneration instructions, do not edit -->`;
  const endMarker = `<!-- end:${name} -->`;
  const beginIdx = draft.indexOf(beginMarker);
  const endIdx = draft.indexOf(endMarker);
  if (beginIdx === -1 || endIdx === -1) {
    throw new Error(`Could not find ${name} section markers in draft`);
  }
  draft =
    draft.slice(0, beginIdx + beginMarker.length) +
    "\n\n" +
    content +
    "\n\n" +
    draft.slice(endIdx);
}

const base = algorithms.filter((entry) => !entry.alg.endsWith("-KE"));
const ke = algorithms.filter((entry) => entry.alg.endsWith("-KE"));
const testVectorSections = [];

for (const entry of base) {
  testVectorSections.push(testVectorSection(entry));
  const keyEncryption = ke.find((candidate) => candidate.alg === `${entry.alg}-KE`);
  if (keyEncryption) {
    testVectorSections.push(testVectorSection(keyEncryption));
  }
}

replaceSection("test-vectors", testVectorSections.join("\n\n"));
writeFileSync(draftPath, draft);
console.log("Draft updated successfully.");
