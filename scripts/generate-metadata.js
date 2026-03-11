import crypto from "crypto";
import path from "path";
import fs from "fs";

const osqueryVersion = "5.22.1";
const sourcekittenVersion = "0.37.2";
const trivyVersion = "v0.68.2";

function computeHash(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  const hashSum = crypto.createHash('sha256');
  hashSum.update(fileBuffer);
  return hashSum.digest('hex');
}

function readHashFromFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return content.split(' ')[0].trim();
  } catch (err) {
    console.warn(`Warning: Could not read hash from ${filePath}`);
    return null;
  }
}

// Fetch the latest release tag from GitHub
async function getLatestGithubRelease(repo) {
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
      headers: { 'User-Agent': '@cdxgen/cdxgen-plugins-bin' }
    });
    const data = await res.json();
    return data.tag_name || 'unknown';
  } catch (err) {
    console.warn(`Warning: Could not fetch latest release for ${repo}`);
    return 'unknown';
  }
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
  const dosaiVersion = await getLatestGithubRelease('owasp-dep-scan/dosai');
  const tools = ['trivy', 'osquery', 'dosai', 'sourcekitten'];
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
    let version = 'unknown';
    let description = `${tool} binary`;
    let purl = '';
    let licenses = [];
    let externalReferences;
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
    if (tool === 'osquery') {
      version = osqueryVersion;
      description = 'SQL powered operating system instrumentation, monitoring, and analytics.';
      purl = `pkg:github/osquery/osquery@${version}`;
      licenses = [{ "expression": "Apache-2.0 OR GPL-2.0-only" }];
      externalReferences = [
        {url: "https://github.com/osquery/osquery", type: "vcs"},
        {url: "https://github.com/osquery/osquery/releases", type: "distribution"},
      ];
    } else if (tool === 'dosai') {
      version = dosaiVersion.replace(/^v/, ''); // strip 'v'
      description = 'Dotnet Source and Assembly Inspector (Dosai) is a tool to list details about the namespaces and methods from sources and assemblies.';
      purl = `pkg:github/owasp-dep-scan/dosai@${version}`;
      licenses = [{ "license": { "id": "MIT" } }];
      externalReferences = [
        {url: "https://github.com/owasp-dep-scan/dosai", type: "vcs"},
        {url: "https://github.com/owasp-dep-scan/dosai/releases", type: "distribution"},
      ];
    } else if (tool === 'trivy') {
      version = trivyVersion;
      description = 'Find vulnerabilities, misconfigurations, secrets, SBOM in containers, Kubernetes, code repositories, clouds and more. This is a custom wrapper maintained by the cdxgen team.';
      purl = `pkg:generic/github.com/cdxgen/cdxgen-plugins-bin/trivy-cdxgen@${version}`;
      licenses = [{ "license": { "id": "Apache-2.0" } }];
      externalReferences = [
        {url: "https://github.com/cdxgen/cdxgen-plugins-bin/tree/main/thirdparty/trivy", type: "vcs"},
        {url: "https://github.com/cdxgen/cdxgen/issues", type: "issue-tracker"},
      ];
    } else if (tool === 'sourcekitten') {
      version = sourcekittenVersion;
      description = 'An adorable little framework and command line tool for interacting with SourceKit.';
      purl = `pkg:github/jpsim/sourcekitten@${version}`;
      licenses = [{ "license": { "id": "MIT" } }];
      externalReferences = [
        {url: "https://github.com/jpsim/SourceKitten", type: "vcs"},
        {url: "https://github.com/jpsim/SourceKitten/issues", type: "issue-tracker"},
        {url: "https://github.com/cdxgen/cdxgen-plugins-bin/pkgs/container/cdxgen-plugins-bin", type: "distribution-intake"},
      ];
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
      ]
    };
    if (shaFile) {
      const fileHash = readHashFromFile(path.join(toolDir, shaFile));
      if (fileHash) {
        component.hashes = [{ alg: "SHA-256", content: fileHash }];
      }
    } else if (!binaryFile.endsWith(".app")) {
      const fileHash = computeHash(`plugins/${tool}/${binaryFile}`);
      component.hashes = [{ alg: "SHA-256", content: fileHash }];
    }
    allComponents.push(component);
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
    // pkg:swift/SourceKitten@unspecified => pkg:github/jpsim/sourcekitten@0.37.2
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
  console.log(`Successfully wrote metadata to ${outFile}`);
}

main().catch(console.error);