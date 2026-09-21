# shared fixture classpath jars

Committed byte-for-byte so the fixtures that reference them from their
`classpath.txt` have a classpath that is an INPUT, not a function of the
machine-local Gradle cache.

- `kotlinx-coroutines-core-jvm-1.8.0.jar` — the real Maven Central artifact
  (sha1 `ac1dc37a30a93150b704022f8d895ee1bd3a36b3`, the content hash Gradle
  stores it under; sha256 in the `.sha256` sidecar). Referenced by the seven
  async fixtures.
