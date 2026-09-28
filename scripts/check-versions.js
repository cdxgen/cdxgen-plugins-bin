// Checks that every copy of the release version matches package.json.
//
// kosi, golem and trustinspector read package.json when they are built. The
// Rust tools cannot: Cargo takes the version from Cargo.toml, so each release
// bump has to edit those files and their lockfiles by hand, along with the
// platform packages and package-lock.json. This script lists every copy that
// was missed.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf-8"));
}

// The `version = "..."` string of one TOML table, or undefined.
function tomlTableVersion(text, table) {
  let inTable = false;
  for (const line of text.split(/\r?\n/)) {
    const header = line.match(/^\s*\[([^\]]+)\]\s*(#.*)?$/);
    if (header) {
      inTable = header[1].trim() === table;
      continue;
    }
    const version = inTable && line.match(/^\s*version\s*=\s*"([^"]*)"/);
    if (version) {
      return version[1];
    }
  }
  return undefined;
}

// The name and version of every package in a Cargo.lock that is built from
// this repository: registry and git packages carry a `source` line, local
// ones do not.
function localLockPackages(text) {
  return text
    .split(/^\[\[package\]\]\s*$/m)
    .slice(1)
    .map((block) => ({
      name: block.match(/^name = "([^"]*)"/m)?.[1],
      version: block.match(/^version = "([^"]*)"/m)?.[1],
      source: block.match(/^source = /m) !== null,
    }))
    .filter((entry) => !entry.source);
}

export function findVersionMismatches(rootDir) {
  const expected = readJson(path.join(rootDir, "package.json")).version;
  const mismatches = [];
  const check = (file, what, actual) => {
    if (actual !== expected) {
      mismatches.push(
        `${path.relative(rootDir, file)}: ${what} is ${actual ?? "missing"}, expected ${expected}`,
      );
    }
  };

  const packagesDir = path.join(rootDir, "packages");
  for (const name of fs.readdirSync(packagesDir).sort()) {
    const file = path.join(packagesDir, name, "package.json");
    if (fs.existsSync(file)) {
      check(file, "version", readJson(file).version);
    }
  }

  const lockFile = path.join(rootDir, "package-lock.json");
  const lock = readJson(lockFile);
  check(lockFile, "version", lock.version);
  check(lockFile, 'packages[""].version', lock.packages?.[""]?.version);

  const thirdpartyDir = path.join(rootDir, "thirdparty");
  for (const name of fs.readdirSync(thirdpartyDir).sort()) {
    const manifest = path.join(thirdpartyDir, name, "Cargo.toml");
    if (!fs.existsSync(manifest)) {
      continue;
    }
    const text = fs.readFileSync(manifest, "utf-8");
    check(
      manifest,
      "version",
      tomlTableVersion(text, "workspace.package") ??
        tomlTableVersion(text, "package"),
    );
    const cargoLock = path.join(thirdpartyDir, name, "Cargo.lock");
    if (fs.existsSync(cargoLock)) {
      for (const entry of localLockPackages(
        fs.readFileSync(cargoLock, "utf-8"),
      )) {
        check(cargoLock, `${entry.name}`, entry.version);
      }
    }
  }
  return { expected, mismatches };
}

const isDirectExecution =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectExecution) {
  const rootDir =
    process.argv[2] ?? fileURLToPath(new URL("..", import.meta.url));
  const { expected, mismatches } = findVersionMismatches(rootDir);
  if (mismatches.length > 0) {
    console.error(`Version mismatches against package.json (${expected}):`);
    for (const mismatch of mismatches) {
      console.error(`  ${mismatch}`);
    }
    process.exit(1);
  }
  console.log(`All versions match package.json (${expected})`);
}
