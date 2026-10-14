/** Adapter-private secret collection, including common JSON storage wrappers. */
export function privateStorageValues(raw: string): readonly string[] {
  const values: string[] = [raw];
  if (raw.length > 16_384) return values;
  const visit = (value: unknown, depth: number) => {
    if (values.length >= 64 || depth > 4) return;
    if (typeof value === 'string' && value) { values.push(value); return; }
    if (value && typeof value === 'object') for (const item of Object.values(value).slice(0, 64)) visit(item, depth + 1);
  };
  try { visit(JSON.parse(raw), 0); } catch { /* Most storage values are plain strings. */ }
  return [...new Set(values)];
}
