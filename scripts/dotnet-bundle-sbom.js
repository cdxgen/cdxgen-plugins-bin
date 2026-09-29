// Builds a CycloneDX SBOM for a .NET single-file executable from the
// <app>.deps.json it bundles.
//
// dosai is downloaded as a published binary, and its release ships no SBOM.
// A single-file publish still carries the dependency manifest the host loads
// the application with: every NuGet package in the binary, its version, its
// SHA-512 and the edges between them. The bundle layout is the one described
// in dotnet/runtime's docs/design/features/single-file-bundle-format.md.
import zlib from "node:zlib";

// The marker the SDK writes into the apphost when it bundles an application.
// The eight bytes before it hold the offset of the bundle header.
const BUNDLE_SIGNATURE = Buffer.from(
  "8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae",
  "hex",
);
const DEPS_JSON_FILE_TYPE = 3;

class BundleReader {
  constructor(buffer, offset) {
    this.buffer = buffer;
    this.offset = offset;
  }

  int32() {
    const value = this.buffer.readInt32LE(this.offset);
    this.offset += 4;
    return value;
  }

  int64() {
    const value = Number(this.buffer.readBigInt64LE(this.offset));
    this.offset += 8;
    return value;
  }

  byte() {
    return this.buffer[this.offset++];
  }

  // A 7-bit encoded length followed by UTF-8 bytes, as BinaryWriter writes it.
  string() {
    let length = 0;
    let shift = 0;
    let next;
    do {
      next = this.byte();
      length |= (next & 0x7f) << shift;
      shift += 7;
    } while (next & 0x80);
    const value = this.buffer.toString(
      "utf-8",
      this.offset,
      this.offset + length,
    );
    this.offset += length;
    return value;
  }
}

// The parsed deps.json of a single-file bundle, or undefined when the file is
// not one.
export function readBundledDepsJson(buffer) {
  const signatureAt = buffer.indexOf(BUNDLE_SIGNATURE);
  if (signatureAt < 8) {
    return undefined;
  }
  const headerOffset = Number(buffer.readBigInt64LE(signatureAt - 8));
  if (headerOffset <= 0 || headerOffset >= buffer.length) {
    return undefined;
  }
  const reader = new BundleReader(buffer, headerOffset);
  const majorVersion = reader.int32();
  reader.int32(); // minor version
  const fileCount = reader.int32();
  reader.string(); // bundle id
  if (majorVersion >= 2) {
    reader.int64(); // deps.json offset
    reader.int64(); // deps.json size
    reader.int64(); // runtimeconfig.json offset
    reader.int64(); // runtimeconfig.json size
    reader.int64(); // flags
  }
  // The manifest entries say whether the file is compressed, which the
  // header's location fields do not.
  for (let index = 0; index < fileCount; index++) {
    const offset = reader.int64();
    const size = reader.int64();
    const compressedSize = majorVersion >= 6 ? reader.int64() : 0;
    const type = reader.byte();
    reader.string(); // relative path
    if (type !== DEPS_JSON_FILE_TYPE) {
      continue;
    }
    const stored = buffer.subarray(offset, offset + (compressedSize || size));
    const text = compressedSize
      ? zlib.inflateRawSync(stored).toString("utf-8")
      : stored.toString("utf-8");
    return JSON.parse(text);
  }
  return undefined;
}

// "sha512-<base64>" as deps.json records it, in hex.
function sha512Hex(value) {
  if (typeof value !== "string" || !value.startsWith("sha512-")) {
    return undefined;
  }
  const hex = Buffer.from(value.slice("sha512-".length), "base64").toString(
    "hex",
  );
  return hex.length === 128 ? hex : undefined;
}

function nugetPurl(name, version) {
  return `pkg:nuget/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

// `root` is the component the SBOM describes; the project entry of deps.json
// (named after the published RID, e.g. Dosai-osx-arm64) is mapped onto it.
export function depsJsonToBom(depsJson, root) {
  const targetName = depsJson?.runtimeTarget?.name;
  const target = depsJson?.targets?.[targetName];
  if (!target || !depsJson.libraries) {
    throw new Error("deps.json has no runtime target");
  }
  const refOf = new Map();
  const components = [];
  let projectKey;
  for (const [key, library] of Object.entries(depsJson.libraries)) {
    const slash = key.lastIndexOf("/");
    const name = key.slice(0, slash);
    const version = key.slice(slash + 1);
    if (library.type === "project") {
      // Only the application itself is a project in a published app;
      // referenced projects are compiled into it.
      if (!projectKey && target[key]) {
        projectKey = key;
        refOf.set(key, root["bom-ref"]);
        continue;
      }
    }
    // A self-contained publish lists the runtime as `runtimepack.<package>`.
    const packageName = name.replace(/^runtimepack\./, "");
    const purl = nugetPurl(packageName, version);
    const component = {
      type: "library",
      name: packageName,
      version,
      purl,
      "bom-ref": purl,
      scope: "required",
    };
    const sha512 = sha512Hex(library.sha512);
    if (sha512) {
      component.hashes = [{ alg: "SHA-512", content: sha512 }];
    }
    refOf.set(key, purl);
    components.push(component);
  }
  const dependencies = [];
  for (const [key, entry] of Object.entries(target)) {
    const ref = refOf.get(key);
    if (!ref) {
      continue;
    }
    const dependsOn = Object.entries(entry.dependencies || {})
      .map(([name, version]) => refOf.get(`${name}/${version}`))
      .filter(Boolean);
    dependencies.push({ ref, dependsOn: [...new Set(dependsOn)].sort() });
  }
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    version: 1,
    metadata: {
      lifecycles: [{ phase: "post-build" }],
      component: root,
    },
    components,
    dependencies,
  };
}
