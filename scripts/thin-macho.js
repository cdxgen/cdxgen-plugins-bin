// Reduces a universal (fat) Mach-O file to a single architecture, in place.
//
// `lipo -thin` does this, but it only exists on macOS and the packages are
// built on Linux. The kept slice is copied byte for byte, which is what `lipo
// -thin` writes too. Every slice of a universal binary carries its own code
// signature, so the result is still validly signed, and a signed .app bundle
// around it still verifies.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const MH_MAGIC_64 = 0xfeedfacf;
// Java class files share FAT_MAGIC; their next word is a version number far
// above any real architecture count.
const MAX_FAT_ARCHS = 32;

export const CPU_TYPES = {
  arm64: 0x0100000c,
  x86_64: 0x01000007,
};

function cpuType(arch) {
  const type = CPU_TYPES[arch];
  if (type === undefined) {
    throw new Error(
      `unsupported architecture ${arch}; expected one of ${Object.keys(CPU_TYPES).join(", ")}`,
    );
  }
  return type;
}

function isThinMachO(buffer, type) {
  return (
    buffer.length >= 8 &&
    buffer.readUInt32LE(0) === MH_MAGIC_64 &&
    buffer.readInt32LE(4) === type
  );
}

function fatArchs(buffer) {
  const magic = buffer.readUInt32BE(0);
  const count = buffer.readUInt32BE(4);
  if (count < 1 || count > MAX_FAT_ARCHS) {
    throw new Error(`fat header lists ${count} architectures`);
  }
  const is64 = magic === FAT_MAGIC_64;
  const entrySize = is64 ? 32 : 20;
  if (buffer.length < 8 + count * entrySize) {
    throw new Error("fat header is truncated");
  }
  const archs = [];
  for (let i = 0; i < count; i++) {
    const at = 8 + i * entrySize;
    archs.push({
      type: buffer.readInt32BE(at),
      offset: is64
        ? Number(buffer.readBigUInt64BE(at + 8))
        : buffer.readUInt32BE(at + 8),
      size: is64
        ? Number(buffer.readBigUInt64BE(at + 16))
        : buffer.readUInt32BE(at + 12),
    });
  }
  return archs;
}

// Returns the bytes of the `arch` slice, or null when `buffer` is already a
// thin Mach-O of that architecture. Throws for anything else, so a changed
// upstream download fails the build instead of shipping the wrong binary.
export function thinSlice(buffer, arch) {
  const type = cpuType(arch);
  if (isThinMachO(buffer, type)) {
    return null;
  }
  const magic = buffer.length >= 8 ? buffer.readUInt32BE(0) : 0;
  if (magic !== FAT_MAGIC && magic !== FAT_MAGIC_64) {
    throw new Error(`not a universal Mach-O file or a thin ${arch} one`);
  }
  const matches = fatArchs(buffer).filter((entry) => entry.type === type);
  if (matches.length !== 1) {
    throw new Error(
      `universal file has ${matches.length} ${arch} slices, expected 1`,
    );
  }
  const [{ offset, size }] = matches;
  if (offset + size > buffer.length) {
    throw new Error(
      `${arch} slice ends at ${offset + size}, past the end of the file (${buffer.length})`,
    );
  }
  const slice = buffer.subarray(offset, offset + size);
  if (!isThinMachO(slice, type)) {
    throw new Error(`${arch} slice is not a 64-bit ${arch} Mach-O file`);
  }
  return slice;
}

// Thins `filePath` to `arch` in place and keeps its mode. Returns the number
// of bytes removed (0 when the file was already thin).
export function thinFile(filePath, arch) {
  const buffer = fs.readFileSync(filePath);
  const slice = thinSlice(buffer, arch);
  if (slice === null) {
    return 0;
  }
  const mode = fs.statSync(filePath).mode & 0o7777;
  const temp = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.thin-${process.pid}`,
  );
  try {
    fs.writeFileSync(temp, slice, { mode });
    fs.chmodSync(temp, mode);
    fs.renameSync(temp, filePath);
  } catch (err) {
    fs.rmSync(temp, { force: true });
    throw err;
  }
  return buffer.length - slice.length;
}

const isDirectExecution =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectExecution) {
  const [arch, filePath] = process.argv.slice(2);
  if (!arch || !filePath) {
    console.error("Usage: node thin-macho.js <arm64|x86_64> <file>");
    process.exit(2);
  }
  try {
    const removed = thinFile(filePath, arch);
    console.log(
      removed === 0
        ? `${filePath} is already a thin ${arch} file`
        : `thinned ${filePath} to ${arch}, ${removed} bytes removed`,
    );
  } catch (err) {
    console.error(`${filePath}: ${err.message}`);
    process.exit(1);
  }
}
