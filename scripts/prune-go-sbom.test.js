import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  GO_FORMULA_REF,
  goToolchainComponent,
  parseGoRelease,
  parseGoVersionM,
  pruneGoSbom,
} from "./prune-go-sbom.js";

const scriptPath = fileURLToPath(
  new URL("./prune-go-sbom.js", import.meta.url),
);

const h1 = `h1:${Buffer.alloc(32, 7).toString("base64")}`;

test("parseGoVersionM reads the release, the modules and their replacements", () => {
  const info = parseGoVersionM(
    [
      "build/tool-linux-amd64: go1.26.8-X:jsonv2",
      "\tpath\ttool",
      "\tmod\ttool\t(devel)\t",
      `\tdep\tgithub.com/ProtonMail/go-crypto\tv1.5.1\t${h1}`,
      "\tdep\tgithub.com/example/old\tv1.0.0",
      `\t=>\tgithub.com/example/fork\tv1.0.1\t${h1}`,
      "\tdep\tgithub.com/example/local\tv0.0.0",
      "\t=>\t../local\t",
      "\tbuild\tCGO_ENABLED=0",
    ].join("\n"),
  );
  assert.equal(info.goVersion, "go1.26.8-X:jsonv2");
  assert.deepEqual(
    info.modules.map((module) => [
      module.path,
      module.version,
      module.replacement?.path,
    ]),
    [
      ["github.com/ProtonMail/go-crypto", "v1.5.1", undefined],
      ["github.com/example/old", "v1.0.0", "github.com/example/fork"],
      ["github.com/example/local", "v0.0.0", undefined],
    ],
  );
});

test("parseGoRelease and goToolchainComponent read the release and experiments", () => {
  assert.deepEqual(parseGoRelease("go1.27.1"), {
    release: "1.27.1",
    experiments: [],
  });
  assert.deepEqual(parseGoRelease("go1.26.8-X:jsonv2,greenteagc"), {
    release: "1.26.8",
    experiments: ["jsonv2", "greenteagc"],
  });
  assert.deepEqual(parseGoRelease("go1.28rc1").release, "1.28rc1");
  assert.equal(parseGoRelease("devel +abc"), undefined);
  assert.equal(goToolchainComponent("devel +abc"), undefined);
  assert.equal(goToolchainComponent("go1.27.1").properties, undefined);
});

function golang(path, version) {
  const purl = `pkg:golang/${path}@${version}`;
  return { type: "library", name: path, version, purl, "bom-ref": purl };
}

test("pruneGoSbom keeps the linked modules and rewires the graph around the rest", () => {
  const root = "pkg:golang/example.com/tool";
  const linked = golang("github.com/protonmail/go-crypto", "v1.5.1");
  const unlinked = golang("cloud.google.com/go/storage", "v1.62.2");
  const behindUnlinked = golang("golang.org/x/sys", "v0.48.0");
  const orphan = golang("golang.org/x/text", "v0.30.0");
  const unlinkedOrphan = golang("golang.org/x/net", "v0.40.0");
  const fork = golang("github.com/example/fork", "v1.0.1");
  const notGo = {
    type: "file",
    name: "LICENSE",
    "bom-ref": "file:LICENSE",
  };
  const bom = {
    metadata: { component: { name: "tool", "bom-ref": root } },
    components: [
      linked,
      unlinked,
      behindUnlinked,
      orphan,
      unlinkedOrphan,
      fork,
      notGo,
    ],
    dependencies: [
      { ref: root, dependsOn: [linked["bom-ref"], unlinked["bom-ref"]] },
      { ref: unlinked["bom-ref"], dependsOn: [behindUnlinked["bom-ref"]] },
      { ref: linked["bom-ref"], dependsOn: [] },
      { ref: fork["bom-ref"], dependsOn: [] },
    ],
  };
  const result = pruneGoSbom(bom, [
    {
      goVersion: "go1.26.8-X:jsonv2",
      modules: [
        { path: "github.com/ProtonMail/go-crypto", version: "v1.5.1" },
        { path: "golang.org/x/sys", version: "v0.48.0" },
        { path: "golang.org/x/text", version: "v0.30.0" },
        {
          path: "github.com/example/old",
          version: "v1.0.0",
          replacement: { path: "github.com/example/fork", version: "v1.0.1" },
        },
        { path: "github.com/example/missing", version: "v2.0.0", sum: h1 },
      ],
    },
  ]);
  assert.deepEqual(result, { dropped: 2, added: 1, toolchains: 1, skipped: [] });
  assert.deepEqual(
    bom.components.map((component) => component["bom-ref"]),
    [
      linked["bom-ref"],
      behindUnlinked["bom-ref"],
      orphan["bom-ref"],
      fork["bom-ref"],
      notGo["bom-ref"],
      "pkg:golang/github.com/example/missing@v2.0.0",
    ],
  );
  // The Go release the binary was built with is not a component; it is in the
  // formulation, with the experiment it was built with.
  assert.ok(!JSON.stringify(bom).includes("stdlib"));
  assert.deepEqual(bom.formulation.map((formula) => formula["bom-ref"]), [
    GO_FORMULA_REF,
  ]);
  const [go] = bom.formulation[0].components;
  assert.equal(go.version, "1.26.8");
  assert.equal(go.type, "platform");
  assert.equal(go.purl, "pkg:generic/go@1.26.8");
  assert.equal(go.description, "go1.26.8-X:jsonv2");
  assert.equal(go["bom-ref"], undefined);
  assert.equal(go.cpe, "cpe:2.3:a:golang:go:1.26.8:*:*:*:*:*:*:*");
  assert.deepEqual(go.properties, [
    { name: "cdx:go:goexperiment", value: "jsonv2" },
  ]);
  const missing = bom.components.find(
    (component) => component.name === "github.com/example/missing",
  );
  assert.deepEqual(missing.hashes, [
    { alg: "SHA-256", content: Buffer.alloc(32, 7).toString("hex") },
  ]);
  const edges = Object.fromEntries(
    bom.dependencies.map((dependency) => [
      dependency.ref,
      dependency.dependsOn,
    ]),
  );
  // x/sys stays reachable through the storage module it was reached by; the
  // modules nothing reaches hang off the root. The file is not a module the
  // build info could vouch for, so it is left where it was.
  assert.deepEqual(edges[root], [
    fork["bom-ref"],
    "pkg:golang/github.com/example/missing@v2.0.0",
    linked["bom-ref"],
    behindUnlinked["bom-ref"],
    orphan["bom-ref"],
  ]);
  assert.equal(edges[unlinked["bom-ref"]], undefined);
  assert.deepEqual(edges[notGo["bom-ref"]], []);
  assert.deepEqual(edges[orphan["bom-ref"]], []);
  // A second run replaces the formula instead of adding another.
  pruneGoSbom(bom, [{ goVersion: "go1.26.8-X:jsonv2", modules: [] }]);
  assert.equal(bom.formulation.length, 1);
});

test("pruneGoSbom skips a binary built from other module versions than go.mod", () => {
  const current = golang("golang.org/x/mod", "v0.41.0");
  const bom = {
    metadata: { component: { "bom-ref": "pkg:golang/example.com/tool" } },
    components: [current],
    dependencies: [],
  };
  const fresh = {
    file: "build/tool-linux-amd64",
    goVersion: "go1.27.1",
    modules: [{ path: "golang.org/x/mod", version: "v0.41.0" }],
  };
  const stale = {
    file: "build/tool-dbg",
    goVersion: "go1.26.5",
    modules: [{ path: "golang.org/x/mod", version: "v0.30.0" }],
  };
  const result = pruneGoSbom(bom, [fresh, stale]);
  assert.deepEqual(
    result.skipped.map(({ info, conflicts }) => [info.file, conflicts.length]),
    [["build/tool-dbg", 1]],
  );
  assert.deepEqual(
    bom.components.map((component) => component.purl),
    ["pkg:golang/golang.org/x/mod@v0.41.0"],
  );
  // The stale binary's Go release is not recorded either.
  assert.deepEqual(
    bom.formulation[0].components.map((component) => component.version),
    ["1.27.1"],
  );
  assert.throws(
    () => pruneGoSbom({ components: [current] }, [stale]),
    /every binary links module versions go.mod does not require/,
  );
});

test("prune-go-sbom fails when no binary has readable build info", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "prune-go-sbom-"));
  try {
    const sbomFile = path.join(tempDir, "sbom.cdx.json");
    const bom = { components: [golang("golang.org/x/sys", "v0.48.0")] };
    fs.writeFileSync(sbomFile, JSON.stringify(bom));
    fs.writeFileSync(path.join(tempDir, "tool-linux-amd64.sha256"), "abc\n");
    const result = spawnSync(
      process.execPath,
      [
        scriptPath,
        sbomFile,
        path.join(tempDir, "tool-linux-amd64.sha256"),
        path.join(tempDir, "tool-*"),
      ],
      { encoding: "utf-8" },
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /No Go build info could be read/);
    assert.deepEqual(JSON.parse(fs.readFileSync(sbomFile, "utf-8")), bom);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
