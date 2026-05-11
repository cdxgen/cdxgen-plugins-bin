import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  computeHash,
  readHashFromFile,
  resolveBinaryHash,
} from "./generate-metadata.js";

const scriptPath = fileURLToPath(new URL("./generate-metadata.js", import.meta.url));

test("readHashFromFile rejects invalid sidecar content", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "generate-metadata-test-"));
  try {
    const hashFile = path.join(tempDir, "binary.sha256");
    fs.writeFileSync(hashFile, "definitely-not-a-sha256\n");
    assert.equal(readHashFromFile(hashFile), null);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("resolveBinaryHash falls back to the computed hash when the sidecar mismatches", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "generate-metadata-test-"));
  try {
    const binaryFile = path.join(tempDir, "tool-linux-amd64");
    const hashFile = `${binaryFile}.sha256`;
    fs.writeFileSync(binaryFile, "trusted-binary");
    fs.writeFileSync(hashFile, `${"0".repeat(64)}  tool-linux-amd64\n`);

    assert.equal(resolveBinaryHash(binaryFile, hashFile), computeHash(binaryFile));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("generate-metadata writes the computed hash to the manifest when the sidecar is invalid", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "generate-metadata-main-"));
  try {
    const toolDir = path.join(tempDir, "trivy");
    fs.mkdirSync(toolDir, { recursive: true });
    const binaryName = "trivy-cdxgen-linux-amd64";
    const binaryFile = path.join(toolDir, binaryName);
    fs.writeFileSync(binaryFile, "binary-payload");
    fs.writeFileSync(path.join(toolDir, `${binaryName}.sha256`), "invalid sha value\n");

    const result = spawnSync(process.execPath, [scriptPath, tempDir], {
      encoding: "utf-8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);

    const manifest = JSON.parse(
      fs.readFileSync(path.join(tempDir, "plugins-manifest.json"), "utf-8"),
    );
    const entry = manifest.plugins.find((plugin) => plugin.name === "trivy");
    assert.ok(entry, "expected trivy manifest entry");
    assert.equal(entry.sha256, computeHash(binaryFile));
    assert.deepEqual(entry.component.hashes, [
      { alg: "SHA-256", content: computeHash(binaryFile) },
    ]);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
