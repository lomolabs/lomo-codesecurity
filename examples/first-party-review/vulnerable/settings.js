export function readSettings(serialized) {
  // Imported settings can execute code in the current process.
  return eval("(" + serialized + ")");
}
