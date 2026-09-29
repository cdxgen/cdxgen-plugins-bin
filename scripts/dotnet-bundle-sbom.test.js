import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { depsJsonToBom, readBundledDepsJson } from "./dotnet-bundle-sbom.js";

const generateMetadata = fileURLToPath(
  new URL("./generate-metadata.js", import.meta.url),
);

const SIGNATURE = Buffer.from(
  "8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae",
  "hex",
);
const sha512 = `sha512-${Buffer.alloc(64, 3).toString("base64")}`;

const depsJson = {
  runtimeTarget: { name: ".NETCoreApp,Version=v10.0/linux-x64" },
  targets: {
    ".NETCoreApp,Version=v10.0/linux-x64": {
      "Dosai-linux-x64/4.1.0": {
        dependencies: {
          "FSharp.Compiler.Service": "43.12.400",
          "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64": "10.0.11",
        },
      },
      "FSharp.Compiler.Service/43.12.400": {
        dependencies: { "FSharp.Core": "10.1.400" },
      },
      "FSharp.Core/10.1.400": {},
      "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/10.0.11": {},
    },
  },
  libraries: {
    "Dosai-linux-x64/4.1.0": { type: "project", serviceable: false },
    "FSharp.Compiler.Service/43.12.400": { type: "package", sha512 },
    "FSharp.Core/10.1.400": { type: "package", sha512 },
    "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/10.0.11": {
      type: "runtimepack",
    },
  },
};

function bundleString(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([Buffer.from([bytes.length]), bytes]);
}

function int64(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigInt64LE(BigInt(value));
  return buffer;
}

function int32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeInt32LE(value);
  return buffer;
}

// An apphost stand-in followed by the bundled files and the bundle header,
// laid out the way the SDK's bundler writes them.
function buildBundle(json, { compress = false, majorVersion = 6 } = {}) {
  const deps = Buffer.from(JSON.stringify(json));
  const storedDeps = compress ? zlib.deflateRawSync(deps) : deps;
  const assembly = Buffer.from("MZ not really an assembly");
  const host = Buffer.alloc(64, 0x90);
  const assemblyOffset = host.length + 8 + SIGNATURE.length;
  const depsOffset = assemblyOffset + assembly.length;
  const headerOffset = depsOffset + storedDeps.length;
  const entry = (offset, size, compressedSize, type, name) =>
    Buffer.concat([
      int64(offset),
      int64(size),
      majorVersion >= 6 ? int64(compressedSize) : Buffer.alloc(0),
      Buffer.from([type]),
      bundleString(name),
    ]);
  const header = Buffer.concat([
    int32(majorVersion),
    int32(0),
    int32(2),
    bundleString("bundle-id"),
    majorVersion >= 2
      ? Buffer.concat([
          int64(depsOffset),
          int64(deps.length),
          int64(0),
          int64(0),
          int64(0),
        ])
      : Buffer.alloc(0),
    entry(assemblyOffset, assembly.length, 0, 1, "Dosai.dll"),
    entry(
      depsOffset,
      deps.length,
      compress ? storedDeps.length : 0,
      3,
      "Dosai.deps.json",
    ),
  ]);
  return Buffer.concat([
    host,
    int64(headerOffset),
    SIGNATURE,
    assembly,
    storedDeps,
    header,
  ]);
}

test("readBundledDepsJson finds the deps.json of a single-file bundle", () => {
  assert.deepEqual(readBundledDepsJson(buildBundle(depsJson)), depsJson);
  assert.deepEqual(
    readBundledDepsJson(buildBundle(depsJson, { compress: true })),
    depsJson,
  );
  assert.deepEqual(
    readBundledDepsJson(buildBundle(depsJson, { majorVersion: 2 })),
    depsJson,
  );
  assert.equal(
    readBundledDepsJson(Buffer.from("\x7fELF plain binary")),
    undefined,
  );
});

test("depsJsonToBom lists the packages with their hashes and edges", () => {
  const root = {
    type: "application",
    name: "dosai",
    version: "4.1.0",
    purl: "pkg:github/owasp-dep-scan/dosai@4.1.0",
    "bom-ref": "pkg:github/owasp-dep-scan/dosai@4.1.0",
  };
  const bom = depsJsonToBom(depsJson, root);
  assert.equal(bom.metadata.component, root);
  assert.deepEqual(
    bom.components.map((component) => component.purl),
    [
      "pkg:nuget/FSharp.Compiler.Service@43.12.400",
      "pkg:nuget/FSharp.Core@10.1.400",
      "pkg:nuget/Microsoft.NETCore.App.Runtime.linux-x64@10.0.11",
    ],
  );
  assert.deepEqual(bom.components[0].hashes, [
    { alg: "SHA-512", content: Buffer.alloc(64, 3).toString("hex") },
  ]);
  assert.equal(bom.components[2].hashes, undefined);
  assert.deepEqual(bom.dependencies, [
    {
      ref: root["bom-ref"],
      dependsOn: [
        "pkg:nuget/FSharp.Compiler.Service@43.12.400",
        "pkg:nuget/Microsoft.NETCore.App.Runtime.linux-x64@10.0.11",
      ],
    },
    {
      ref: "pkg:nuget/FSharp.Compiler.Service@43.12.400",
      dependsOn: ["pkg:nuget/FSharp.Core@10.1.400"],
    },
    { ref: "pkg:nuget/FSharp.Core@10.1.400", dependsOn: [] },
    {
      ref: "pkg:nuget/Microsoft.NETCore.App.Runtime.linux-x64@10.0.11",
      dependsOn: [],
    },
  ]);
});

test("generate-metadata writes dosai's SBOM from the bundled deps.json", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "dosai-sbom-"));
  try {
    const toolDir = path.join(tempDir, "dosai");
    fs.mkdirSync(toolDir);
    fs.writeFileSync(
      path.join(toolDir, "dosai-linux-amd64"),
      buildBundle(depsJson, { compress: true }),
    );
    const result = spawnSync(process.execPath, [generateMetadata, tempDir], {
      encoding: "utf-8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const manifest = JSON.parse(
      fs.readFileSync(path.join(tempDir, "plugins-manifest.json"), "utf-8"),
    );
    const entry = manifest.plugins.find((plugin) => plugin.name === "dosai");
    assert.equal(entry.sbomFile, "plugins/dosai/sbom-dosai-postbuild.cdx.json");
    const sbom = JSON.parse(
      fs.readFileSync(
        path.join(toolDir, "sbom-dosai-postbuild.cdx.json"),
        "utf-8",
      ),
    );
    assert.equal(
      sbom.metadata.component["bom-ref"],
      entry.component["bom-ref"],
    );
    const aggregate = JSON.parse(
      fs.readFileSync(path.join(tempDir, "sbom-postbuild.cdx.json"), "utf-8"),
    );
    assert.deepEqual(
      aggregate.dependencies.find(
        (dependency) => dependency.ref === entry.component["bom-ref"],
      ).dependsOn,
      [
        "pkg:nuget/FSharp.Compiler.Service@43.12.400",
        "pkg:nuget/Microsoft.NETCore.App.Runtime.linux-x64@10.0.11",
      ],
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("generate-metadata leaves dosai without an SBOM when the binary is not a bundle", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "dosai-sbom-"));
  try {
    fs.mkdirSync(path.join(tempDir, "dosai"));
    fs.writeFileSync(path.join(tempDir, "dosai", "dosai-linux-amd64"), "ELF");
    const result = spawnSync(process.execPath, [generateMetadata, tempDir], {
      encoding: "utf-8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stderr, /not a \.NET single-file bundle/);
    const manifest = JSON.parse(
      fs.readFileSync(path.join(tempDir, "plugins-manifest.json"), "utf-8"),
    );
    assert.equal(
      manifest.plugins.find((plugin) => plugin.name === "dosai").sbomFile,
      undefined,
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
