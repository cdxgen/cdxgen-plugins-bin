// Debug mode flag
const DEBUG_MODE =
  process.env.CDXGEN_DEBUG_MODE === "debug" ||
  process.env.NODE_ENV === "development";

if (DEBUG_MODE) {
  console.log("cdxgen plugins check");
}
