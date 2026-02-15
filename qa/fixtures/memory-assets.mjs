export function createMemoryAssets() {
  const objects = new Map(); // key -> { bytes: Uint8Array, metadata: { contentType?: string } }

  return {
    async put(key, value, options = {}) {
      const storageKey = String(key || '').trim();
      if (!storageKey) throw new Error('Missing key');

      const bytes = value instanceof Uint8Array
        ? value
        : value instanceof ArrayBuffer
          ? new Uint8Array(value)
          : ArrayBuffer.isView(value)
            ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
            : null;

      if (!bytes) throw new Error('Unsupported value type for put()');

      const meta = options && typeof options === 'object' ? options.metadata : null;
      const contentType = meta && typeof meta.contentType === 'string' ? meta.contentType : '';

      objects.set(storageKey, {
        bytes: new Uint8Array(bytes),
        metadata: contentType ? { contentType } : {},
      });
    },

    async getWithMetadata(key, options = {}) {
      const storageKey = String(key || '').trim();
      if (!storageKey) return null;
      const object = objects.get(storageKey) || null;
      if (!object) return null;

      const type = options && typeof options === 'object' ? options.type : null;
      const bytes = object.bytes;

      if (type === 'arrayBuffer') {
        // Ensure we return a standalone ArrayBuffer (not a view onto a larger buffer).
        const copy = new Uint8Array(bytes);
        return { value: copy.buffer, metadata: object.metadata || {} };
      }

      // Default to ArrayBuffer for our test usage.
      const copy = new Uint8Array(bytes);
      return { value: copy.buffer, metadata: object.metadata || {} };
    },

    // Test-only helper.
    __unsafe_listKeys() {
      return Array.from(objects.keys());
    },
  };
}

