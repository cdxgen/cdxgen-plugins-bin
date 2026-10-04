import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  computeHash,
  mergeByRef,
  readHashFromFile,
  resolveBinaryHash,
  sbomComponents,
  trivyVersionFromGoMod,
} from "./generate-metadata.js";

const scriptPath = fileURLToPath(
  new URL("./generate-metadata.js", import.meta.url),
);

test("trivyVersionFromGoMod takes the pinned Trivy release and adds -cdx", () => {
  const goMod =
    "module example\n\ngo 1.26.8\n\nrequire (\n\tgithub.com/aquasecurity/trivy v0.74.0\n\tgithub.com/spf13/cobra v1.10.2\n)\n";
  assert.equal(trivyVersionFromGoMod(goMod), "0.74.0-cdx");
  assert.throws(
    () => trivyVersionFromGoMod("module example\n"),
    /does not require github.com\/aquasecurity\/trivy/,
  );
});

test("readHashFromFile rejects invalid sidecar content", () => {
  const tempDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "generate-metadata-test-"),
  );
  try {
    const hashFile = path.join(tempDir, "binary.sha256");
    fs.writeFileSync(hashFile, "definitely-not-a-sha256\n");
    assert.equal(readHashFromFile(hashFile), null);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("resolveBinaryHash falls back to the computed hash when the sidecar mismatches", () => {
  const tempDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "generate-metadata-test-"),
  );
  try {
    const binaryFile = path.join(tempDir, "tool-linux-amd64");
    const hashFile = `${binaryFile}.sha256`;
    fs.writeFileSync(binaryFile, "trusted-binary");
    fs.writeFileSync(hashFile, `${"0".repeat(64)}  tool-linux-amd64\n`);

    assert.equal(
      resolveBinaryHash(binaryFile, hashFile),
      computeHash(binaryFile),
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("generate-metadata writes the computed hash to the manifest when the sidecar is invalid", () => {
  const tempDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "generate-metadata-main-"),
  );
  try {
    const toolDir = path.join(tempDir, "trivy");
    fs.mkdirSync(toolDir, { recursive: true });
    const binaryName = "trivy-cdxgen-linux-amd64";
    const binaryFile = path.join(toolDir, binaryName);
    fs.writeFileSync(binaryFile, "binary-payload");
    fs.writeFileSync(
      path.join(toolDir, `${binaryName}.sha256`),
      "invalid sha value\n",
    );

    const result = spawnSync(process.execPath, [scriptPath, tempDir], {
      encoding: "utf-8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);

    const manifest = JSON.parse(
      fs.readFileSync(path.join(tempDir, "plugins-manifest.json"), "utf-8"),
    );
    const entry = manifest.plugins.find((plugin) => plugin.name === "trivy");
    assert.ok(entry, "expected trivy manifest entry");
    const trivyVersion = trivyVersionFromGoMod(
      fs.readFileSync(
        new URL("../thirdparty/trivy/go.mod", import.meta.url),
        "utf-8",
      ),
    );
    assert.match(trivyVersion, /^\d+\.\d+\.\d+-cdx$/);
    assert.equal(entry.component.version, trivyVersion);
    assert.equal(
      entry.component.purl,
      `pkg:generic/github.com/cdxgen/cdxgen-plugins-bin/trivy-cdxgen@${trivyVersion}`,
    );
    assert.equal(entry.sha256, computeHash(binaryFile));
    assert.deepEqual(entry.component.hashes, [
      { alg: "SHA-256", content: computeHash(binaryFile) },
    ]);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("generate-metadata records Rusi helper metadata", () => {
  const tempDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "generate-metadata-rusi-"),
  );
  try {
    const toolDir = path.join(tempDir, "rusi");
    fs.mkdirSync(toolDir, { recursive: true });
    const binaryName = "rusi-linuxmusl-amd64";
    const binaryFile = path.join(toolDir, binaryName);
    fs.writeFileSync(binaryFile, "rusi-binary-payload");

    const result = spawnSync(process.execPath, [scriptPath, tempDir], {
      encoding: "utf-8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);

    const manifest = JSON.parse(
      fs.readFileSync(path.join(tempDir, "plugins-manifest.json"), "utf-8"),
    );
    const entry = manifest.plugins.find((plugin) => plugin.name === "rusi");
    assert.ok(entry, "expected rusi manifest entry");
    assert.equal(entry.binaryPath, `plugins/rusi/${binaryName}`);
    assert.equal(
      entry.component.purl,
      `pkg:generic/github.com/cdxgen/cdxgen-plugins-bin/rusi@${manifest.package.version}`,
    );
    assert.deepEqual(entry.component.licenses, [{ license: { id: "MIT" } }]);
    assert.equal(entry.sha256, computeHash(binaryFile));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("sbomComponents adds the modules listed under metadata.component", () => {
  const module = (name) => ({
    type: "application",
    name,
    "bom-ref": `pkg:maven/kosi/${name}@4.1.1?type=jar`,
  });
  const components = sbomComponents({
    metadata: {
      component: {
        name: "kosi",
        components: [
          { ...module("kosi-cli"), components: [module("kosi-front")] },
          module("kosi-front"),
        ],
      },
    },
    components: [module("kosi-schema")],
  });
  assert.deepEqual(
    components.map((component) => component.name),
    ["kosi-schema", "kosi-cli", "kosi-front"],
  );
  assert.equal(components[1].components, undefined);
});

test("mergeByRef keeps one component per bom-ref and drops edges to missing ones", () => {
  const merged = mergeByRef(
    [
      {
        name: "serde",
        "bom-ref": "pkg:cargo/serde@1.0.228",
        scope: "required",
      },
      { name: "serde", "bom-ref": "pkg:cargo/serde@1.0.228" },
      { name: "rusi", "bom-ref": "rusi" },
      { name: "cdxrs", "bom-ref": "cdxrs" },
    ],
    [
      { ref: "rusi", dependsOn: ["pkg:cargo/serde@1.0.228"] },
      {
        ref: "cdxrs",
        dependsOn: ["pkg:cargo/serde@1.0.228", "pkg:swift/X@unspecified"],
      },
      { ref: "cdxrs", dependsOn: ["pkg:cargo/serde@1.0.228"] },
      { ref: "pkg:swift/X@unspecified", dependsOn: ["rusi"] },
    ],
  );
  assert.equal(merged.components.length, 3);
  assert.equal(merged.components[0].scope, "required");
  assert.deepEqual(merged.dependencies, [
    { ref: "rusi", dependsOn: ["pkg:cargo/serde@1.0.228"] },
    { ref: "cdxrs", dependsOn: ["pkg:cargo/serde@1.0.228"] },
  ]);
});

test("generate-metadata records cdxrs and cdxui and merges their SBOMs", () => {
  const tempDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "generate-metadata-rust-"),
  );
  try {
    const sharedCrate = {
      type: "library",
      name: "serde",
      version: "1.0.228",
      purl: "pkg:cargo/serde@1.0.228",
      "bom-ref": "pkg:cargo/serde@1.0.228",
    };
    for (const tool of ["cdxrs", "cdxui"]) {
      const toolDir = path.join(tempDir, tool);
      fs.mkdirSync(toolDir, { recursive: true });
      fs.writeFileSync(
        path.join(toolDir, `${tool}-linux-amd64`),
        `${tool}-binary`,
      );
      const rootRef = `pkg:cargo/${tool}@4.1.1`;
      fs.writeFileSync(
        path.join(toolDir, `sbom-${tool}-postbuild.cdx.json`),
        JSON.stringify({
          metadata: { component: { name: tool, "bom-ref": rootRef } },
          // cargo lists the tool's own crate as a component as well
          components: [{ name: tool, "bom-ref": rootRef }, sharedCrate],
          dependencies: [
            { ref: rootRef, dependsOn: [sharedCrate["bom-ref"]] },
            { ref: sharedCrate["bom-ref"], dependsOn: [] },
          ],
        }),
      );
    }
    const result = spawnSync(process.execPath, [scriptPath, tempDir], {
      encoding: "utf-8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const manifest = JSON.parse(
      fs.readFileSync(path.join(tempDir, "plugins-manifest.json"), "utf-8"),
    );
    const aggregate = JSON.parse(
      fs.readFileSync(path.join(tempDir, "sbom-postbuild.cdx.json"), "utf-8"),
    );
    const refs = aggregate.components.map((component) => component["bom-ref"]);
    for (const tool of ["cdxrs", "cdxui"]) {
      const entry = manifest.plugins.find((plugin) => plugin.name === tool);
      assert.ok(entry, `expected ${tool} manifest entry`);
      assert.equal(
        entry.component.purl,
        `pkg:generic/github.com/cdxgen/cdxgen-plugins-bin/${tool}@${manifest.package.version}`,
      );
      assert.equal(
        entry.sbomFile,
        `plugins/${tool}/sbom-${tool}-postbuild.cdx.json`,
      );
      assert.ok(!refs.includes(`pkg:cargo/${tool}@4.1.1`));
      assert.deepEqual(
        aggregate.dependencies.find(
          (dependency) => dependency.ref === entry.component["bom-ref"],
        ).dependsOn,
        ["pkg:cargo/serde@1.0.228"],
      );
    }
    assert.equal(
      refs.filter((ref) => ref === "pkg:cargo/serde@1.0.228").length,
      1,
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
