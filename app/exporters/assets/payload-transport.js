/* Offline JSON decoding; only controlled exporter roots call this codec.
 * Provider values are never recursively interpreted as transport descriptors. */
function gansarReadStoredJson(input) {
  const value = typeof input === "string" ? JSON.parse(input) : input;
  if (!value || typeof value !== "object" || !Object.prototype.hasOwnProperty.call(value, "__gansar_json_storage__")) return value;
  if (Object.keys(value).length !== 1) throw new Error("Invalid JSON storage envelope");
  const data = value.__gansar_json_storage__;
  if (!data || !(data.version === 1 && data.encoding === "gzip-base64" || data.version === 2 && data.encoding === "gzip-base64-string-table") || !Number.isSafeInteger(data.bytes)
      || data.bytes < 1 || data.bytes > 2147483647 || !Number.isInteger(data.crc32)
      || typeof data.data !== "string" || data.data.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(data.data)) throw new Error("Invalid JSON storage descriptor");
  const binary = atob(data.data), compressed = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) compressed[i] = binary.charCodeAt(i);
  if (compressed.length < 18 || compressed[0] !== 31 || compressed[1] !== 139 || compressed[2] !== 8) throw new Error("Invalid JSON gzip member");
  const trailer = new DataView(compressed.buffer, compressed.byteOffset + compressed.byteLength - 8, 8);
  if (trailer.getUint32(4, true) !== data.bytes || trailer.getUint32(0, true) !== data.crc32) throw new Error("JSON gzip length/checksum differs from index");
  const raw = fflate.gunzipSync(compressed, {out: new Uint8Array(data.bytes)});
  if (raw.length !== data.bytes) throw new Error("JSON storage size mismatch");
  if (!gansarReadStoredJson.crcTable) {
    gansarReadStoredJson.crcTable = Uint32Array.from({length: 256}, (_, n) => {
      for (let k = 0; k < 8; k++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1;
      return n >>> 0;
    });
  }
  let crc = 0xffffffff;
  for (const byte of raw) crc = gansarReadStoredJson.crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
  if (((crc ^ 0xffffffff) >>> 0) !== (data.crc32 >>> 0)) throw new Error("JSON storage checksum mismatch");
  const decoded = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(raw));
  if (data.version === 1) return decoded;
  if (!decoded || !Array.isArray(decoded.strings) || decoded.strings.length > 200000
      || decoded.strings.some(value => typeof value !== "string")
      || !Object.prototype.hasOwnProperty.call(decoded, "value")) throw new Error("Invalid JSON string table");
  const restore = value => {
    if (typeof value !== "string" || !value.startsWith("\0")) return value;
    if (value.startsWith("\0\0")) return value.slice(1);
    const ref = value.slice(1);
    if (!/^(0|[1-9][0-9]*)$/.test(ref) || !Number.isSafeInteger(Number(ref)) || Number(ref) >= decoded.strings.length) throw new Error("Invalid JSON string reference");
    return decoded.strings[Number(ref)];
  };
  decoded.value = restore(decoded.value);
  const pending = [decoded.value];
  while (pending.length) {
    const node = pending.pop();
    if (!node || typeof node !== "object") continue;
    for (const key of Object.keys(node)) {
      node[key] = restore(node[key]);
      if (node[key] && typeof node[key] === "object") pending.push(node[key]);
    }
  }
  return decoded.value;
}
