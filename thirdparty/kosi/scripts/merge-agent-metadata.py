#!/usr/bin/env python3
"""Merges native-image tracing-agent outputs into one reachability-metadata.json.

Usage: merge-agent-metadata.py <agent-run-root> <out-file>

Each child directory of <agent-run-root> holds one run's
reachability-metadata.json (one fixture). The merge is a deterministic union:
type entries keyed by type name, method/field lists unioned per type, proxy
groups and resources deduplicated by canonical JSON. The same inputs always
produce byte-identical output so CI can diff the checked-in file.
"""
import json
import os
import re
import sys

# The tracing agent records whichever AWT locale properties the agent
# host's default locale loads (awt_en_GB on a British host, awt_en_US on a
# US one), so an un-normalized merge makes native-metadata host-dependent
# and native-metadata-check fails on the other side of the Atlantic. kosi
# never renders anything (the no-op toolkit is selected before AWT loads),
# so one canonical English variant is a build-input fact, not an analysis
# fact. Normalize every locale-suffixed sun/awt/resources glob to en_US.
AWT_LOCALE_GLOB = re.compile(r"^(sun/awt/resources/awt[a-z]*_)[a-z]{2,3}(_[A-Z]{2})?\.properties$")


def canonicalize(entry):
    glob_value = entry.get("glob")
    if isinstance(glob_value, str):
        match = AWT_LOCALE_GLOB.match(glob_value)
        if match and not glob_value.endswith("_en_US.properties"):
            entry = dict(entry)
            entry["glob"] = match.group(1) + "en_US.properties"
    return entry


def canon(x):
    return json.dumps(x, sort_keys=True)


def merge():
    root, out_path = sys.argv[1], sys.argv[2]
    reflection, resources = {}, {}
    # Reflection entries under jdk.internal.* describe the substrate of the
    # native image itself (docs/KOSI.md defect 3: the jimage reader for the
    # resolved tier's JDK). The tracing agent runs on the JVM, where that
    # code path never executes, so regeneration would silently drop them.
    # Seed the union from the checked-in output before merging agent runs.
    if os.path.exists(out_path):
        previous = json.load(open(out_path))
        for entry in previous.get("resources", []):
            entry = canonicalize(entry)
            resources[canon(entry)] = entry
        for entry in previous.get("reflection", []):
            t = entry.get("type")
            if isinstance(t, str) and t.startswith("jdk.internal."):
                reflection.setdefault(("type", t), {k: v for k, v in entry.items() if k != "type"} | {"type": t})
    for slug in sorted(os.listdir(root)):
        path = os.path.join(root, slug, "reachability-metadata.json")
        if not os.path.exists(path):
            continue
        doc = json.load(open(path))
        for entry in doc.get("reflection", []):
            t = entry.get("type")
            if isinstance(t, dict):  # proxy group
                key = ("proxy", canon(t))
            else:
                key = ("type", t or "")
            slot = reflection.setdefault(key, {k: v for k, v in entry.items() if k != "type"} | {"type": t})
            for lk, lv in entry.items():
                if lk == "type":
                    continue
                if isinstance(lv, list):
                    seen = {canon(x) for x in slot.setdefault(lk, [])}
                    slot[lk].extend(x for x in lv if canon(x) not in seen)
                else:
                    slot[lk] = lv
        for entry in doc.get("resources", []):
            entry = canonicalize(entry)
            resources[canon(entry)] = entry

    def sort_entries(entries):
        return sorted(entries, key=canon)

    merged = {
        "reflection": sort_entries(list(reflection.values())),
        "resources": sort_entries(list(resources.values())),
    }
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(merged, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"merged {len(reflection)} reflection entries, {len(resources)} resources -> {out_path}")


if __name__ == "__main__":
    merge()
