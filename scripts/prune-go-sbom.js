// Restricts a Go helper's post-build SBOM to the modules its binaries link.
//
// `cdxgen -t go` reads go.mod, which lists every module in the build graph.
// trivy-cdxgen vendors all of Trivy and cuts most of it out at build time
// through overlay/patches, so go.mod names about four times the modules the
// binary contains. The build info each Go binary embeds (`go version -m`) is
// the exact list: this script keeps the components it names, adds any it names
// that cdxgen missed, records the Go standard library the binary was built
// with, and rewires the dependency graph around the modules it drops.
//
// Usage: node prune-go-sbom.js <sbom.cdx.json> <binary>...
// Files ending in .sha256 or .json are ignored, so a shell glob over the build
// directory can be passed as is. A binary whose build info cannot be read (a
// UPX-packed one, for instance) is skipped with a warning; at least one must
// be readable.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Parses `go version -m` output into the Go release and the linked modules.
// A `=>` line replaces the module on the line before it and is recorded on
// that module as `replacement`, since cdxgen may name either one.
export function parseGoVersionM(text) {
  let goVersion;
  const modules = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const firstLine = rawLine.match(/^\S.*:\s+(go\S+)\s*$/);
    if (firstLine) {
      goVersion = firstLine[1];
      continue;
    }
    const fields = rawLine.trim().split("\t");
    if (fields[0] === "dep" && fields.length >= 3) {
      modules.push({ path: fields[1], version: fields[2], sum: fields[3] });
    } else if (fields[0] === "=>" && fields.length >= 3 && modules.length) {
      // A local-directory replacement carries no version; the original
      // module then still identifies the code.
      modules[modules.length - 1].replacement = {
        path: fields[1],
        version: fields[2],
        sum: fields[3],
      };
    }
  }
  return { goVersion, modules };
}

export function readBuildInfo(binaryPath) {
  const text = execFileSync("go", ["version", "-m", binaryPath], {
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return { file: binaryPath, ...parseGoVersionM(text) };
}

// The module path and version a pkg:golang purl names, lowercased the way
// cdxgen writes them.
function golangKey(purl) {
  if (typeof purl !== "string" || !purl.startsWith("pkg:golang/")) {
    return undefined;
  }
  const body = purl.slice("pkg:golang/".length).split(/[?#]/)[0];
  const at = body.lastIndexOf("@");
  if (at <= 0) {
    return undefined;
  }
  return `${decodeURIComponent(body.slice(0, at)).toLowerCase()}@${decodeURIComponent(body.slice(at + 1))}`;
}

function moduleKey(module) {
  return `${module.path.toLowerCase()}@${module.version}`;
}

// go.sum's h1: hash is a base64 SHA-256, the value cdxgen records as hex.
function h1ToSha256Hex(sum) {
  if (typeof sum !== "string" || !sum.startsWith("h1:")) {
    return undefined;
  }
  const hex = Buffer.from(sum.slice(3), "base64").toString("hex");
  return hex.length === 64 ? hex : undefined;
}

function moduleComponent(module) {
  const purl = `pkg:golang/${module.path.toLowerCase()}@${module.version}`;
  const component = {
    type: "library",
    name: module.path,
    version: module.version,
    purl,
    "bom-ref": purl,
    scope: "required",
  };
  const sha256 = h1ToSha256Hex(module.sum);
  if (sha256) {
    component.hashes = [{ alg: "SHA-256", content: sha256 }];
  }
  return component;
}

// `go1.26.8-X:jsonv2` names the release and the GOEXPERIMENT it was built
// with; the standard library's version is the release alone.
export function goReleaseVersion(goVersion) {
  const match = goVersion.match(/^go(\d+(?:\.\d+)*(?:(?:rc|beta)\d+)?)/);
  return match ? `v${match[1]}` : undefined;
}

function stdlibComponent(goVersion) {
  const version = goReleaseVersion(goVersion);
  if (!version) {
    return undefined;
  }
  const purl = `pkg:golang/stdlib@${version}`;
  return {
    type: "library",
    name: "stdlib",
    version,
    description: "The Go standard library the binary was built with.",
    purl,
    "bom-ref": purl,
    scope: "required",
  };
}

// The modules of a binary that go.mod requires at another version: the binary
// was built from other sources than the SBOM describes, such as a stale file
// left in the build directory.
export function conflictingModules(bom, info) {
  const versionsByPath = new Map();
  for (const component of bom.components || []) {
    const key = golangKey(component.purl);
    if (!key) {
      continue;
    }
    const at = key.lastIndexOf("@");
    const path = key.slice(0, at);
    versionsByPath.set(path, [
      ...(versionsByPath.get(path) || []),
      key.slice(at + 1),
    ]);
  }
  const agrees = (module) => {
    const versions = versionsByPath.get(module.path.toLowerCase());
    return !versions || versions.includes(module.version);
  };
  return info.modules.filter(
    (module) =>
      !agrees(module) && !(module.replacement && agrees(module.replacement)),
  );
}

// Returns what changed, and the binaries left out because conflictingModules
// found them built from other sources.
export function pruneGoSbom(bom, allBuildInfos) {
  const skipped = [];
  const buildInfos = [];
  for (const info of allBuildInfos) {
    const conflicts = conflictingModules(bom, info);
    if (conflicts.length) {
      skipped.push({ info, conflicts });
    } else {
      buildInfos.push(info);
    }
  }
  if (!buildInfos.length) {
    throw new Error(
      "every binary links module versions go.mod does not require; rebuild them first",
    );
  }
  // Each linked module with the keys cdxgen may know it by: its own and, when
  // go.mod replaces it, the replacement's.
  const linked = new Map();
  const goVersions = new Set();
  for (const info of buildInfos) {
    if (info.goVersion) {
      goVersions.add(info.goVersion);
    }
    for (const module of info.modules) {
      const keys = [moduleKey(module)];
      if (module.replacement) {
        keys.push(moduleKey(module.replacement));
      }
      linked.set(keys.join(" "), { module, keys });
    }
  }
  const linkedKeys = new Set([...linked.values()].flatMap(({ keys }) => keys));
  const rootRef = bom.metadata?.component?.["bom-ref"];
  const kept = [];
  const keptRefs = new Set();
  // The kept components the build info names, as opposed to the rest of the
  // SBOM (anything that is not a Go module), which is left as it is.
  const linkedRefs = new Set();
  const dropped = new Set();
  const present = new Set();
  for (const component of bom.components || []) {
    const key = golangKey(component.purl);
    if (key && !linkedKeys.has(key)) {
      dropped.add(component["bom-ref"]);
      continue;
    }
    if (key) {
      present.add(key);
      linkedRefs.add(component["bom-ref"]);
    }
    kept.push(component);
    keptRefs.add(component["bom-ref"]);
  }
  const added = [];
  for (const { module, keys } of linked.values()) {
    if (keys.some((key) => present.has(key))) {
      continue;
    }
    // The replacement is the code that was linked.
    const component = moduleComponent(module.replacement || module);
    if (keptRefs.has(component["bom-ref"])) {
      continue;
    }
    kept.push(component);
    keptRefs.add(component["bom-ref"]);
    linkedRefs.add(component["bom-ref"]);
    added.push(component["bom-ref"]);
  }
  for (const goVersion of [...goVersions].sort()) {
    const component = stdlibComponent(goVersion);
    if (component && !keptRefs.has(component["bom-ref"])) {
      kept.push(component);
      keptRefs.add(component["bom-ref"]);
      linkedRefs.add(component["bom-ref"]);
      added.push(component["bom-ref"]);
    }
  }

  // An edge into a dropped module is replaced by the edges that module led to,
  // so a kept module stays reachable through the ones the binary does not
  // contain.
  const edges = new Map();
  for (const dependency of bom.dependencies || []) {
    edges.set(dependency.ref, [
      ...(edges.get(dependency.ref) || []),
      ...(dependency.dependsOn || []),
    ]);
  }
  const keptTargets = (ref) => {
    const result = new Set();
    const seen = new Set([ref]);
    const stack = [...(edges.get(ref) || [])];
    while (stack.length) {
      const next = stack.pop();
      if (seen.has(next)) {
        continue;
      }
      seen.add(next);
      if (dropped.has(next)) {
        stack.push(...(edges.get(next) || []));
      } else if (keptRefs.has(next) || next === rootRef) {
        result.add(next);
      }
    }
    return result;
  };
  const dependencies = new Map();
  for (const ref of edges.keys()) {
    if (dropped.has(ref)) {
      continue;
    }
    dependencies.set(ref, keptTargets(ref));
  }
  if (rootRef) {
    const rootTargets = dependencies.get(rootRef) || new Set();
    for (const ref of added) {
      rootTargets.add(ref);
    }
    dependencies.set(rootRef, rootTargets);
    // Every module the build info names is linked into the binary, so one the
    // pruned graph no longer reaches hangs off the root.
    const reachable = new Set([rootRef]);
    const visit = (start) => {
      const stack = [start];
      while (stack.length) {
        for (const next of dependencies.get(stack.pop()) || []) {
          if (!reachable.has(next)) {
            reachable.add(next);
            stack.push(next);
          }
        }
      }
    };
    visit(rootRef);
    for (const ref of linkedRefs) {
      if (!reachable.has(ref)) {
        rootTargets.add(ref);
        reachable.add(ref);
        visit(ref);
      }
    }
  }
  for (const ref of keptRefs) {
    if (!dependencies.has(ref)) {
      dependencies.set(ref, new Set());
    }
  }
  bom.components = kept;
  bom.dependencies = [...dependencies]
    .map(([ref, dependsOn]) => ({ ref, dependsOn: [...dependsOn].sort() }))
    .sort((a, b) => a.ref.localeCompare(b.ref));
  return { dropped: dropped.size, added: added.length, skipped };
}

function isCandidateBinary(file) {
  return (
    !file.endsWith(".sha256") &&
    !file.endsWith(".json") &&
    fs.existsSync(file) &&
    fs.statSync(file).isFile()
  );
}

const isDirectExecution =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectExecution) {
  const [sbomFile, ...binaries] = process.argv.slice(2);
  if (!sbomFile || !binaries.length) {
    console.error("Usage: node prune-go-sbom.js <sbom.cdx.json> <binary>...");
    process.exit(1);
  }
  const buildInfos = [];
  for (const binary of binaries.filter(isCandidateBinary)) {
    try {
      const info = readBuildInfo(binary);
      if (!info.modules.length && !info.goVersion) {
        throw new Error("no build info");
      }
      buildInfos.push(info);
    } catch (err) {
      console.warn(
        `Warning: could not read the Go build info of ${binary}: ${err.message.split("\n")[0]}`,
      );
    }
  }
  if (!buildInfos.length) {
    console.error(
      `No Go build info could be read from ${binaries.join(" ")}; ${sbomFile} was left unpruned.`,
    );
    process.exit(1);
  }
  const bom = JSON.parse(fs.readFileSync(sbomFile, "utf-8"));
  let result;
  try {
    result = pruneGoSbom(bom, buildInfos);
  } catch (err) {
    console.error(`${sbomFile} was left unpruned: ${err.message}`);
    process.exit(1);
  }
  const { dropped, added, skipped } = result;
  for (const { info, conflicts } of skipped) {
    const sample = conflicts
      .slice(0, 3)
      .map((module) => `${module.path} ${module.version}`)
      .join(", ");
    console.warn(
      `Warning: skipped ${info.file}, which links module versions go.mod does not require (${sample}); it is stale or built from other sources`,
    );
  }
  fs.writeFileSync(sbomFile, JSON.stringify(bom, null, 2));
  console.log(
    `${sbomFile}: kept ${bom.components.length} components, dropped ${dropped} modules the binaries do not link, added ${added}`,
  );
}
