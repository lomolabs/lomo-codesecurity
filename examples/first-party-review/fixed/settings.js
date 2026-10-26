export function readSettings(serialized) {
  // Parse a data format before applying application-specific validation.
  return JSON.parse(serialized);
}
