import assert from "node:assert/strict";
import test from "node:test";

import { withCentralMirror } from "./maven-central-mirror.js";

const MIRROR = "https://maven-central.storage-download.googleapis.com/maven2";

test("adds a central mirror to an empty settings file", () => {
  const xml = withCentralMirror("");
  assert.ok(xml.includes("<mirrorOf>central</mirrorOf>"));
  assert.ok(xml.includes(`<url>${MIRROR}</url>`));
  assert.ok(xml.trim().endsWith("</settings>"));
});

test("keeps existing servers and mirrors", () => {
  const existing =
    '<settings><servers><server><id>x</id></server></servers><mirrors><mirror><id>other</id></mirror></mirrors></settings>';
  const xml = withCentralMirror(existing);
  assert.ok(xml.includes("<id>x</id>"));
  assert.ok(xml.includes("<id>other</id>"));
  assert.ok(xml.includes(`<url>${MIRROR}</url>`));
});

test("is idempotent", () => {
  const once = withCentralMirror("");
  assert.equal(withCentralMirror(once), once);
});
