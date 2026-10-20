import { createHash } from 'node:crypto';

// Normalize only equivalent placeholder spelling. Prefixes, names and slashes stay significant.
export function routePath(value) {
  return value.replace(/<(?:(?:int|float|uuid|string|path):)?([A-Za-z_]\w*)>/g, ':$1')
    .replace(/\{([A-Za-z_]\w*)\}/g, ':$1');
}
export const bodyLocation = value => ['json', 'form', 'body', 'xml'].includes(value) ? 'body' : value;
export function routeMatches(endpoint, reference) {
  return endpoint.method === reference.method && routePath(endpoint.path) === routePath(reference.path);
}
export function scoreRoutes(endpoints, references) {
  return references.map(reference => ({ ...reference, matched: endpoints.some(endpoint => routeMatches(endpoint, reference)) }));
}
export function scoreParameters(endpoints, references) {
  return references.map(reference => ({ ...reference, matched: endpoints.some(endpoint => routeMatches(endpoint, reference)
    && endpoint.parameters.some(parameter => parameter.name === reference.name && bodyLocation(parameter.location) === reference.location)) }));
}
export function inventoryDigest(endpoints) {
  const rows = endpoints.map(endpoint => JSON.stringify({ method: endpoint.method, path: endpoint.path,
    parameters: endpoint.parameters.map(parameter => `${parameter.location}:${parameter.name}`).sort(),
    sources: endpoint.sources.map(source => `${source.file}:${source.line}`).sort() })).sort();
  return createHash('sha256').update(JSON.stringify(rows)).digest('hex');
}
export function systematicSample(endpoints, size = 5) {
  const unique = [...new Map(endpoints.map(endpoint => [`${endpoint.method} ${endpoint.path}`, endpoint])).values()]
    .sort((a, b) => `${a.method} ${a.path}`.localeCompare(`${b.method} ${b.path}`, 'en'));
  if (unique.length <= size) return unique;
  return Array.from({ length: size }, (_, index) => unique[Math.floor(index * (unique.length - 1) / (size - 1))]);
}
