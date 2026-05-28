import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const pluginsPackageJson = JSON.parse(
  fs.readFileSync(new URL("../package.json", import.meta.url), "utf-8"),
);
const osqueryVersion = "5.23.0";
const sourcekittenVersion = "0.37.3";
const trivyVersion = "v0.68.2";
const dosaiVersion = "v3.0.5";
const trustInspectorVersion = pluginsPackageJson.version;
const golemVersion = pluginsPackageJson.version;

function pluginComponentMetadata() {
  return {
    osquery: {
      version: osqueryVersion,
      description:
        "SQL powered operating system instrumentation, monitoring, and analytics.",
      purl: `pkg:github/osquery/osquery@${osqueryVersion}`,
      licenses: [{ expression: "Apache-2.0 OR GPL-2.0-only" }],
      externalReferences: [
        { url: "https://github.com/osquery/osquery", type: "vcs" },
        { url: "https://github.com/osquery/osquery/releases", type: "distribution" },
      ],
    },
    dosai: {
      version: dosaiVersion.replace(/^v/, ""),
      description:
        "Dotnet Source and Assembly Inspector (Dosai) is a tool to list details about the namespaces and methods from sources and assemblies.",
      purl: `pkg:github/owasp-dep-scan/dosai@${dosaiVersion.replace(/^v/, "")}`,
      licenses: [{ license: { id: "MIT" } }],
      externalReferences: [
        { url: "https://github.com/owasp-dep-scan/dosai", type: "vcs" },
        {
          url: "https://github.com/owasp-dep-scan/dosai/releases",
          type: "distribution",
        },
      ],
    },
    trivy: {
      version: trivyVersion,
      description:
        "Find vulnerabilities, misconfigurations, secrets, SBOM in containers, Kubernetes, code repositories, clouds and more. This is a custom wrapper maintained by the cdxgen team.",
      purl: `pkg:generic/github.com/cdxgen/cdxgen-plugins-bin/trivy-cdxgen@${trivyVersion}`,
      licenses: [{ license: { id: "Apache-2.0" } }],
      externalReferences: [
        {
          url: "https://github.com/cdxgen/cdxgen-plugins-bin/tree/main/thirdparty/trivy",
          type: "vcs",
        },
        { url: "https://github.com/cdxgen/cdxgen/issues", type: "issue-tracker" },
      ],
    },
    sourcekitten: {
      version: sourcekittenVersion,
      description:
        "An adorable little framework and command line tool for interacting with SourceKit.",
      purl: `pkg:github/jpsim/sourcekitten@${sourcekittenVersion}`,
      licenses: [{ license: { id: "MIT" } }],
      externalReferences: [
        { url: "https://github.com/jpsim/SourceKitten", type: "vcs" },
        {
          url: "https://github.com/jpsim/SourceKitten/issues",
          type: "issue-tracker",
        },
        {
          url: "https://github.com/cdxgen/cdxgen-plugins-bin/pkgs/container/cdxgen-plugins-bin",
          type: "distribution-intake",
        },
      ],
    },

    golem: {
      version: golemVersion,
      description:
        "Go Library Evidence Mapper (golem) extracts semantic Go source evidence and optional call graphs for cdxgen.",
      purl: `pkg:generic/github.com/cdxgen/cdxgen-plugins-bin/golem@${golemVersion}`,
      licenses: [{ license: { id: "Apache-2.0" } }],
      externalReferences: [
        {
          url: "https://github.com/cdxgen/cdxgen-plugins-bin/tree/main/thirdparty/golem",
          type: "vcs",
        },
        { url: "https://github.com/cdxgen/cdxgen/issues", type: "issue-tracker" },
      ],
    },
    trustinspector: {
      version: trustInspectorVersion,
      description:
        "cdxgen trust-material inspection helper for repository keys, certificate stores, macOS code-signing, notarization, and Windows trust policy inventory.",
      purl: `pkg:generic/github.com/cdxgen/cdxgen-plugins-bin/trustinspector-cdxgen@${trustInspectorVersion}`,
      licenses: [{ license: { id: "Apache-2.0" } }],
      externalReferences: [
        {
          url: "https://github.com/cdxgen/cdxgen-plugins-bin/tree/main/thirdparty/trustinspector",
          type: "vcs",
        },
        { url: "https://github.com/cdxgen/cdxgen/issues", type: "issue-tracker" },
      ],
    },
  };
}

export function computeHash(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  const hashSum = crypto.createHash('sha256');
  hashSum.update(fileBuffer);
  return hashSum.digest('hex');
}

function isSha256Hex(value) {
  return /^[a-f0-9]{64}$/i.test(value);
}

export function readHashFromFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const hashValue = content.split(/\s+/)[0].trim();
    if (!isSha256Hex(hashValue)) {
      console.warn(`Warning: Ignoring invalid SHA-256 content in ${filePath}`);
      return null;
    }
    return hashValue.toLowerCase();
  } catch (err) {
    console.warn(`Warning: Could not read hash from ${filePath}`);
    return null;
  }
}

export function resolveBinaryHash(binaryFilePath, shaFilePath) {
  const computedHash = computeHash(binaryFilePath);
  if (!shaFilePath) {
    return computedHash;
  }
  const sidecarHash = readHashFromFile(shaFilePath);
  if (sidecarHash && sidecarHash === computedHash) {
    return computedHash;
  }
  if (sidecarHash) {
    console.warn(
      `Warning: Ignoring mismatched SHA-256 in ${shaFilePath}; using computed hash for ${binaryFilePath}`,
    );
  }
  return computedHash;
}

async function main() {
  const targetDir = process.argv[2];
  if (!targetDir || !fs.existsSync(targetDir)) {
    console.error(`Usage: node generate-metadata.js <path-to-plugins-dir>`);
    process.exit(1);
  }
  console.log(`Generating metadata for plugins in: ${targetDir}`);
  const allComponents = [];
  const allDependencies = [];
  const toolMetadata = pluginComponentMetadata();
  const manifestPlugins = [];
  const tools = ['trivy', 'osquery', 'dosai', 'sourcekitten', 'trustinspector', 'golem'];
  for (const tool of tools) {
    const toolDir = path.join(targetDir, tool);
    if (!fs.existsSync(toolDir)) {
      continue;
    }
    const files = fs.readdirSync(toolDir);
    const shaFile = files.find(f => f.endsWith('.sha256'));
    const sbomFile = files.find(f => f.endsWith('.cdx.json'));
    const binaryFile = files.find(f => !f.endsWith('.sha256') && !f.endsWith('.json'));
    if (!binaryFile) {
      continue;
    }
    const toolInfo = toolMetadata[tool] || {};
    let version = toolInfo.version || 'unknown';
    let description = toolInfo.description || `${tool} binary`;
    let purl = toolInfo.purl || '';
    let licenses = toolInfo.licenses || [];
    let externalReferences = toolInfo.externalReferences;
    const evidence = {
      "identity": [
        {
          "field": "purl",
          "confidence": 1,
          "methods": [
            {
              "technique": "attestation",
              "confidence": 1
            }
          ]
        }
      ]
    }
    const component = {
      type: "application",
      name: tool,
      version: version,
      description: description,
      purl: purl,
      "bom-ref": purl,
      licenses,
      evidence,
      externalReferences,
      properties: [
        {
          name: "internal:binary_path",
          value: `plugins/${tool}/${binaryFile}`
        },
        {
          name: "cdx:plugin:manifest:name",
          value: tool,
        },
      ]
    };
    let fileHash = null;
    if (shaFile) {
      if (binaryFile.endsWith(".app")) {
        fileHash = readHashFromFile(path.join(toolDir, shaFile));
      } else {
        fileHash = resolveBinaryHash(
          path.join(toolDir, binaryFile),
          path.join(toolDir, shaFile),
        );
      }
    } else if (!binaryFile.endsWith(".app")) {
      fileHash = computeHash(path.join(toolDir, binaryFile));
    }
    if (fileHash) {
      component.hashes = [{ alg: "SHA-256", content: fileHash }];
    }
    allComponents.push(component);
    manifestPlugins.push({
      name: tool,
      version,
      binaryPath: `plugins/${tool}/${binaryFile}`,
      sha256: fileHash || undefined,
      sbomFile: sbomFile ? `plugins/${tool}/${sbomFile}` : undefined,
      component,
    });
    if (sbomFile) {
      try {
        const sbomContent = JSON.parse(fs.readFileSync(path.join(toolDir, sbomFile), 'utf-8'));
        const originalRootRef = sbomContent.metadata?.component?.["bom-ref"];
        if (sbomContent.components) {
          allComponents.push(...sbomContent.components.filter((c) => c?.version !== "unspecified"));
        }
        if (sbomContent.dependencies) {
          for (const dep of sbomContent.dependencies) {
            const newDep = { ...dep };
            if (originalRootRef && newDep.ref === originalRootRef) {
              newDep.ref = component["bom-ref"];
            }
            if (originalRootRef && newDep.dependsOn && Array.isArray(newDep.dependsOn)) {
              newDep.dependsOn = newDep.dependsOn.map(r => r === originalRootRef ? component["bom-ref"] : r);
            }

            allDependencies.push(newDep);
          }
        }
      } catch (err) {
        console.warn(`Warning: Failed to parse/merge SBOM for ${tool} (${sbomFile}):`, err);
      }
    }
  }
  const outData = { bomFormat: "CycloneDX", specVersion: "1.7", version: 1, metadata: {timestamp: `${new Date().toISOString().split(".")[0]}Z`, lifecycles: [{phase: "post-build"}]}, components: allComponents };
  if (allDependencies.length > 0) {
    // Fix the sourcekitten ref
    // pkg:swift/SourceKitten@unspecified => pkg:github/jpsim/sourcekitten@0.37.3
    for (const d of allDependencies) {
      if (d.ref === "pkg:swift/SourceKitten@unspecified") {
        d.ref = `pkg:github/jpsim/sourcekitten@${sourcekittenVersion}`;
        break;
      }
    }
    outData.dependencies = allDependencies;
  }
  const outFile = path.join(targetDir, 'sbom-postbuild.cdx.json');
  fs.writeFileSync(outFile, JSON.stringify(outData, null, null));
  const manifestFile = path.join(targetDir, 'plugins-manifest.json');
  fs.writeFileSync(
    manifestFile,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        package: {
          name: pluginsPackageJson.name,
          version: pluginsPackageJson.version,
          repository: pluginsPackageJson.repository?.url,
          homepage: pluginsPackageJson.homepage,
        },
        plugins: manifestPlugins,
      },
      null,
      2,
    ),
  );
  console.log(`Successfully wrote metadata to ${outFile}`);
  console.log(`Successfully wrote metadata manifest to ${manifestFile}`);
}

const isDirectExecution = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectExecution) {
  main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}
