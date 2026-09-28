import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { CPU_TYPES, thinFile, thinSlice } from "./thin-macho.js";

const scriptPath = fileURLToPath(new URL("./thin-macho.js", import.meta.url));

// A thin 64-bit Mach-O stand-in: the magic, the CPU type, then filler.
function machO(arch, length, fill) {
  const buffer = Buffer.alloc(length, fill);
  buffer.writeUInt32LE(0xfeedfacf, 0);
  buffer.writeInt32LE(CPU_TYPES[arch], 4);
  return buffer;
}

// A universal file holding `slices` at 4 KiB-aligned offsets, as lipo lays
// them out.
function universal(slices, { fat64 = false } = {}) {
  const entrySize = fat64 ? 32 : 20;
  const header = Buffer.alloc(8 + slices.length * entrySize);
  header.writeUInt32BE(fat64 ? 0xcafebabf : 0xcafebabe, 0);
  header.writeUInt32BE(slices.length, 4);
  const parts = [header];
  let offset = header.length;
  slices.forEach(({ arch, bytes }, i) => {
    const aligned = Math.ceil(offset / 4096) * 4096;
    parts.push(Buffer.alloc(aligned - offset));
    const at = 8 + i * entrySize;
    header.writeInt32BE(CPU_TYPES[arch], at);
    if (fat64) {
      header.writeBigUInt64BE(BigInt(aligned), at + 8);
      header.writeBigUInt64BE(BigInt(bytes.length), at + 16);
      header.writeUInt32BE(12, at + 24);
    } else {
      header.writeUInt32BE(aligned, at + 8);
      header.writeUInt32BE(bytes.length, at + 12);
      header.writeUInt32BE(12, at + 16);
    }
    parts.push(bytes);
    offset = aligned + bytes.length;
  });
  return Buffer.concat(parts);
}

const x86 = machO("x86_64", 5000, 0x11);
const arm = machO("arm64", 7000, 0x22);

test("thinSlice returns the arm64 slice of a universal file byte for byte", () => {
  for (const fat64 of [false, true]) {
    const fat = universal(
      [
        { arch: "x86_64", bytes: x86 },
        { arch: "arm64", bytes: arm },
      ],
      { fat64 },
    );
    assert.deepEqual(thinSlice(fat, "arm64"), arm);
    assert.deepEqual(thinSlice(fat, "x86_64"), x86);
  }
});

test("thinSlice leaves a thin file of the wanted architecture alone", () => {
  assert.equal(thinSlice(arm, "arm64"), null);
});

test("thinSlice rejects files it cannot thin to the wanted architecture", () => {
  assert.throws(() => thinSlice(x86, "arm64"), /not a universal Mach-O file/);
  assert.throws(
    () => thinSlice(Buffer.from("#!/bin/sh\n"), "arm64"),
    /not a universal Mach-O file/,
  );
  assert.throws(
    () => thinSlice(universal([{ arch: "x86_64", bytes: x86 }]), "arm64"),
    /has 0 arm64 slices/,
  );
  assert.throws(
    () =>
      thinSlice(
        universal([
          { arch: "arm64", bytes: arm },
          { arch: "arm64", bytes: arm },
        ]),
        "arm64",
      ),
    /has 2 arm64 slices/,
  );
  const fat = universal([
    { arch: "x86_64", bytes: x86 },
    { arch: "arm64", bytes: arm },
  ]);
  assert.throws(
    () => thinSlice(fat.subarray(0, fat.length - 1), "arm64"),
    /past the end of the file/,
  );
  // A slice whose own header disagrees with the fat header.
  assert.throws(
    () => thinSlice(universal([{ arch: "arm64", bytes: x86 }]), "arm64"),
    /is not a 64-bit arm64 Mach-O/,
  );
  // A Java class file: same magic, then a version number.
  const javaClass = Buffer.from([
    0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x41,
  ]);
  assert.throws(() => thinSlice(javaClass, "arm64"), /lists 65 architectures/);
  assert.throws(() => thinSlice(fat, "ppc"), /unsupported architecture ppc/);
});

test("the CLI thins in place, keeps the mode, and is a no-op on a thin file", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "thin-macho-test-"));
  try {
    const target = path.join(tempDir, "osqueryd");
    const fat = universal([
      { arch: "x86_64", bytes: x86 },
      { arch: "arm64", bytes: arm },
    ]);
    fs.writeFileSync(target, fat);
    fs.chmodSync(target, 0o750);

    const first = spawnSync(process.execPath, [scriptPath, "arm64", target], {
      encoding: "utf-8",
    });
    assert.equal(first.status, 0, first.stderr);
    assert.match(
      first.stdout,
      new RegExp(`${fat.length - arm.length} bytes removed`),
    );
    assert.deepEqual(fs.readFileSync(target), arm);
    assert.equal(fs.statSync(target).mode & 0o7777, 0o750);

    const second = spawnSync(process.execPath, [scriptPath, "arm64", target], {
      encoding: "utf-8",
    });
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /already a thin arm64 file/);
    assert.deepEqual(fs.readdirSync(tempDir), ["osqueryd"]);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("the CLI fails loudly and leaves the file untouched when it cannot thin", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "thin-macho-test-"));
  try {
    const target = path.join(tempDir, "osqueryd");
    fs.writeFileSync(target, x86);
    const result = spawnSync(process.execPath, [scriptPath, "arm64", target], {
      encoding: "utf-8",
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /not a universal Mach-O file/);
    assert.deepEqual(fs.readFileSync(target), x86);
    assert.deepEqual(fs.readdirSync(tempDir), ["osqueryd"]);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("thinFile returns the number of bytes removed", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "thin-macho-test-"));
  try {
    const target = path.join(tempDir, "bin");
    const fat = universal([
      { arch: "arm64", bytes: arm },
      { arch: "x86_64", bytes: x86 },
    ]);
    fs.writeFileSync(target, fat);
    assert.equal(thinFile(target, "arm64"), fat.length - arm.length);
    assert.equal(thinFile(target, "arm64"), 0);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
