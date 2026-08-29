# osquery: live operating system instrumentation

[osquery](https://github.com/osquery/osquery) exposes an operating system as a relational database and answers SQL queries against it. This repository packages upstream release binaries so cdxgen can use them for OBOM (operating system BOM) collection and host-level evidence. Nothing is forked or patched; the binaries are downloaded from upstream releases by `scripts/thirdparty-downloads.sh`, verified, and repackaged per platform.

cdxgen invokes osquery during host-level scans when the binary is present. A custom build or a manually installed copy can be wired in with `OSQUERY_CMD`.

## What it collects

Because the host is queried as tables, one engine covers everything cdxgen needs for an OBOM:

Installed software, from the package databases and application registries of each platform. Running processes with their metadata. File system state and configuration. Network connections and listening sockets. This is live data, not manifest data, which is what makes it useful for compliance questions such as whether running systems match their declared inventory, or whether an unauthorized process or configuration has appeared.

## Why SQL matters here

A single query joins facts that would otherwise need a different tool per platform. Listing installed software with versions on Linux, macOS, and Windows is normally three codepaths; in osquery it is one query over the `packages` table, and everything else cdxgen collects follows the same pattern. The repackaged binary carries the full osquery CLI, so anything you can express as a query during a manual investigation is available, not just the queries cdxgen runs.

## Direct usage

The packaged binary is the standard `osqueryi` interactive shell and `osqueryd` daemon. To explore a host the way cdxgen does:

```bash
osqueryi "SELECT name, version, source FROM packages LIMIT 10;"
osqueryi "SELECT pid, name, path FROM processes WHERE path != '' LIMIT 10;"
osqueryi "SELECT * from os_version;"
```

## Platforms

linux-amd64, linux-arm64, darwin-arm64, windows-amd64, and windows-arm64.

## Provenance and trust

The binaries are upstream release artifacts, fetched by pinned URL and hashed during packaging, with `.sha256` sidecars published alongside them on GitHub Releases. They are not rebuilt from source here, so upstream's release integrity is what you inherit. If your trust model requires compiled-from-source binaries, osquery is the one helper in this repository where you would build it yourself and point `OSQUERY_CMD` at the result.
