import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { findVersionMismatches } from "./check-versions.js";

const scriptPath = fileURLToPath(
  new URL("./check-versions.js", import.meta.url),
);
const repoRoot = fileURLToPath(new URL("..", import.meta.url));

function write(root, file, content) {
  const target = path.join(root, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(
    target,
    typeof content === "string" ? content : JSON.stringify(content, null, 2),
  );
}

// A repository laid out like this one, every copy at `version` unless
// `overrides` names a different one.
function fixture(version, overrides = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "check-versions-test-"));
  const v = (key) => overrides[key] ?? version;
  write(root, "package.json", { name: "plugins", version });
  write(root, "package-lock.json", {
    name: "plugins",
    version: v("lock"),
    packages: { "": { name: "plugins", version: v("lockRoot") } },
  });
  write(root, "packages/linux-amd64/package.json", { version: v("linux") });
  write(root, "packages/darwin-arm64/package.json", { version: v("darwin") });
  write(
    root,
    "thirdparty/tool/Cargo.toml",
    `[package]\nname = "tool"\nversion = "${v("tool")}"\n\n[dependencies]\nserde = { version = "1" }\n`,
  );
  write(
    root,
    "thirdparty/tool/Cargo.lock",
    `version = 4\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "tool"\nversion = "${v("toolLock")}"\n`,
  );
  write(
    root,
    "thirdparty/ws/Cargo.toml",
    `[workspace]\nmembers = ["cli"]\n\n[workspace.package]\nversion = "${v("ws")}"\nedition = "2024"\n`,
  );
  write(
    root,
    "thirdparty/ws/Cargo.lock",
    `version = 4\n\n[[package]]\nname = "ws-cli"\nversion = "${v("wsLock")}"\n`,
  );
  write(root, "thirdparty/gotool/Makefile", "version ?= 0.0.0\n");
  return root;
}

test("a repository where every copy matches has no mismatches", () => {
  const root = fixture("1.2.3");
  try {
    assert.deepEqual(findVersionMismatches(root), {
      expected: "1.2.3",
      mismatches: [],
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("every stale copy is reported, and registry packages are ignored", () => {
  const root = fixture("1.2.3", {
    lock: "1.2.2",
    lockRoot: "1.2.2",
    darwin: "1.2.2",
    tool: "1.2.2",
    toolLock: "1.2.2",
    ws: "1.2.2",
    wsLock: "1.2.2",
  });
  try {
    assert.deepEqual(findVersionMismatches(root).mismatches, [
      "packages/darwin-arm64/package.json: version is 1.2.2, expected 1.2.3",
      "package-lock.json: version is 1.2.2, expected 1.2.3",
      'package-lock.json: packages[""].version is 1.2.2, expected 1.2.3',
      "thirdparty/tool/Cargo.toml: version is 1.2.2, expected 1.2.3",
      "thirdparty/tool/Cargo.lock: tool is 1.2.2, expected 1.2.3",
      "thirdparty/ws/Cargo.toml: version is 1.2.2, expected 1.2.3",
      "thirdparty/ws/Cargo.lock: ws-cli is 1.2.2, expected 1.2.3",
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a Cargo.toml without a version is reported as missing", () => {
  const root = fixture("1.2.3");
  try {
    write(root, "thirdparty/tool/Cargo.toml", '[package]\nname = "tool"\n');
    assert.deepEqual(findVersionMismatches(root).mismatches, [
      "thirdparty/tool/Cargo.toml: version is missing, expected 1.2.3",
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the CLI exits 1 and names each stale file", () => {
  const root = fixture("1.2.3", { tool: "1.2.2" });
  try {
    const result = spawnSync(process.execPath, [scriptPath, root], {
      encoding: "utf-8",
    });
    assert.equal(result.status, 1);
    assert.match(
      result.stderr,
      /thirdparty\/tool\/Cargo\.toml: version is 1\.2\.2, expected 1\.2\.3/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("this repository's versions all match package.json", () => {
  assert.deepEqual(findVersionMismatches(repoRoot).mismatches, []);
});
