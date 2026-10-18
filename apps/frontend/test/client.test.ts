import { describe, expect, it } from 'vitest';
import type { DiscoveryResult } from '@agento/discovery';
import { createFixtureClient, createHttpClient, parseSavedDiscovery, validateProjectInput } from '../src/client';
import type { ProjectInput } from '../src/client';
import { demoDiscovery } from '../src/data/demo-discovery';

const validInput: ProjectInput = {
  name: 'Customer portal', repositoryPath: '/work/customer-portal',
  baseUrl: 'https://portal.example.test/api', allowedOrigins: ['https://portal.example.test'],
};
const client = () => createFixtureClient({ delayMs: 0 });
const discoveryAt = (repositoryPath: string): DiscoveryResult => ({ ...demoDiscovery, repositoryPath, name: 'customer-portal' });

describe('project validation', () => {
  it('requires a name and repository path with errors attached to the fields', () => {
    expect(validateProjectInput({ ...validInput, name: ' ', repositoryPath: '' })).toEqual({
      name: 'Enter a project name.', repositoryPath: 'Enter a repository path.',
    });
  });

  it('accepts HTTP(S) paths and an explicit normalized target origin', () => {
    expect(validateProjectInput(validInput)).toEqual({});
    expect(validateProjectInput({ ...validInput, baseUrl: 'HTTPS://portal.example.test:443/api',
      allowedOrigins: ['https://portal.example.test/'] })).toEqual({});
    expect(validateProjectInput({ ...validInput, baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] })).toEqual({});
  });

  it.each(['ftp://portal.example.test', 'javascript:alert(1)', '/relative', 'https:portal.example.test',
    'https://user:secret@portal.example.test', 'https://@portal.example.test',
    'https://portal.example.test\n/hidden', 'https://portal.example.test\\other'])('rejects target %s without echoing it', (baseUrl) => {
    const result = validateProjectInput({ ...validInput, baseUrl });
    expect(result.baseUrl).toBe('Enter an HTTP or HTTPS target URL without credentials.');
    expect(JSON.stringify(result)).not.toContain(baseUrl);
  });

  it.each(['*', 'https://*.example.test', 'https://portal.example.test/api',
    'https://portal.example.test?scope=all', 'https://portal.example.test?',
    'https://portal.example.test#secret', 'https://portal.example.test#',
    'https://user:secret@portal.example.test'])('rejects invalid allowlist origin %s', (origin) => {
    expect(validateProjectInput({ ...validInput, allowedOrigins: [origin] }).allowedOrigins).toBeDefined();
  });

  it('requires an allowlist that includes the target origin', () => {
    expect(validateProjectInput({ ...validInput, allowedOrigins: [] }).allowedOrigins).toBe('Declare at least one allowed origin.');
    expect(validateProjectInput({ ...validInput, allowedOrigins: ['https://other.example.test'] }).allowedOrigins)
      .toBe('The allowlist must include the target URL origin.');
  });

  it('rejects control characters and excessively long fields', () => {
    expect(validateProjectInput({ ...validInput, repositoryPath: '/work\u0000/app' }).repositoryPath).toBeDefined();
    expect(validateProjectInput({ ...validInput, name: 'a'.repeat(121) }).name).toBeDefined();
    expect(validateProjectInput({ ...validInput, allowedOrigins: Array.from({ length: 101 }, () => 'https://portal.example.test') }).allowedOrigins).toBeDefined();
  });
});

describe('saved discovery uploads', () => {
  it('accepts real discovery shape and returns an isolated copy', () => {
    const result = parseSavedDiscovery(demoDiscovery);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toEqual(demoDiscovery);
    expect(result.value).not.toBe(demoDiscovery);
    expect(result.value.dependencies).not.toBe(demoDiscovery.dependencies);
  });

  it.each([null, undefined, true, 'secret contents', 4, [], {}, { name: 'only a name' }])('rejects malformed upload %#', (value) => {
    expect(parseSavedDiscovery(value)).toEqual({ ok: false, error: 'This file is not a valid saved AgentO discovery result.' });
  });

  it('validates deeply nested enums, arrays, booleans, and source counts', () => {
    const malformed = [
      { ...demoDiscovery, authentication: ['oauth-unknown'] },
      { ...demoDiscovery, dependencies: [{ name: 'express' }] },
      { ...demoDiscovery, dependencies: [{ ...demoDiscovery.dependencies[0], kind: 'transitive' }] },
      { ...demoDiscovery, middleware: [{ kind: 'cors', name: 'x', file: 'x', basis: 'header', line: 0 }] },
      { ...demoDiscovery, structure: { ...demoDiscovery.structure, sourceFileCount: -1 } },
      { ...demoDiscovery, structure: { ...demoDiscovery.structure, sourceFileCount: 1.5 } },
      { ...demoDiscovery, structure: { ...demoDiscovery.structure, manifests: [{}] } },
      { ...demoDiscovery, expressAdapterAvailable: 'false' },
      { ...demoDiscovery, mode: 'code-aware', supportedCodeAwareMode: false },
      { ...demoDiscovery, diagnostics: [{ code: 'bogus', file: 'secret-file', message: 'secret' }] },
      { ...demoDiscovery, fallbackReasons: {} },
      { ...demoDiscovery, name: 'a'.repeat(4097) },
      { ...demoDiscovery, languages: Array.from({ length: 20001 }, () => 'typescript') },
    ];
    for (const value of malformed) expect(parseSavedDiscovery(value).ok).toBe(false);
  });

  it('rejects inherited fields, prototype pollution keys, and class objects', () => {
    expect(parseSavedDiscovery(Object.create(demoDiscovery)).ok).toBe(false);
    const polluted = JSON.parse(JSON.stringify(demoDiscovery)) as Record<string, unknown>;
    Object.defineProperty(polluted, '__proto__', { value: { secret: 'do not echo' }, enumerable: true });
    expect(parseSavedDiscovery(polluted)).toEqual({ ok: false, error: 'This file is not a valid saved AgentO discovery result.' });
    expect(parseSavedDiscovery({ ...demoDiscovery, structure: new Date() }).ok).toBe(false);
  });

  it('does not invoke accessors and sanitizes proxy failures', () => {
    let invoked = false;
    const value = { ...demoDiscovery };
    Object.defineProperty(value, 'name', { enumerable: true, get() { invoked = true; throw new Error('credential-secret'); } });
    expect(parseSavedDiscovery(value).ok).toBe(false);
    expect(invoked).toBe(false);
    const hostile = new Proxy({}, { getPrototypeOf() { throw new Error('credential-secret'); } });
    expect(parseSavedDiscovery(hostile)).toEqual({ ok: false, error: 'This file is not a valid saved AgentO discovery result.' });
  });

  it('rejects sparse, custom-property, and accessor arrays', () => {
    const sparse = new Array(1);
    const custom = ['typescript'];
    Object.defineProperty(custom, 'extra', { value: 'secret', enumerable: true });
    const accessor: unknown[] = [];
    Object.defineProperty(accessor, '0', { enumerable: true, get() { throw new Error('do not invoke'); } });
    for (const languages of [sparse, custom, accessor]) expect(parseSavedDiscovery({ ...demoDiscovery, languages }).ok).toBe(false);
  });

  it('rejects oversized valid-shaped results with a generic error', () => {
    const value = { ...demoDiscovery, fallbackReasons: Array.from({ length: 600 }, () => 'a'.repeat(4096)) };
    expect(parseSavedDiscovery(value).ok).toBe(false);
  });
});

describe('replaceable fixture client', () => {
  it('loads a real saved demo discovery and fixture statuses with linked details', async () => {
    const api = client();
    expect((await api.listProjects()).map((project) => project.id)).toEqual(['demo-shop']);
    expect(await api.getDiscovery('demo-shop')).toEqual(demoDiscovery);
    const scan = await api.getScan('demo-shop');
    expect(scan.source).toBe('demo-fixture');
    expect(scan.stages.some((stage) => stage.status === 'unavailable')).toBe(true);
    const findings = await api.getFindings('demo-shop');
    expect(new Set(findings.map((finding) => finding.status))).toEqual(new Set(['HYPOTHESIS', 'LIKELY', 'CONFIRMED', 'NOT_REPRODUCED', 'REJECTED']));
    for (const finding of findings) {
      expect(finding.sourceType).toBe('demo-fixture');
      expect(finding.rootCause).toBeTruthy();
      expect(finding.endpoint?.id).toBe(finding.endpointId);
      expect(finding.evidence.map((evidence) => evidence.id)).toEqual(finding.evidenceIds);
      expect(finding.evidence.every((evidence) => evidence.facts.fixture === true)).toBe(true);
      expect(finding.evidence.every((evidence) => evidence.projectId === finding.projectId && evidence.endpointId === finding.endpointId)).toBe(true);
      expect(finding.endpoint?.evidenceIds).toEqual(finding.evidenceIds);
      expect(finding.remediation.findingId).toBe(finding.id);
      expect(finding.remediation.evidenceIds).toEqual(finding.evidenceIds);
      expect(await api.getFinding('demo-shop', finding.id)).toEqual(finding);
    }
    expect(new Set(findings.flatMap((finding) => finding.evidenceIds)).size).toBe(findings.flatMap((finding) => finding.evidence).length);
    const confirmed = findings.find((finding) => finding.status === 'CONFIRMED')!;
    expect(confirmed.evidence.map((evidence) => evidence.kind)).toEqual(['source-location', 'http-response']);
    expect(confirmed.evidence[0]?.source).toEqual(confirmed.source);
    expect(confirmed.evidence[1]?.facts).toMatchObject({ fixture: true, synthetic: true, responseBodyRedacted: true,
      identityLabel: 'customer-A', ownerLabel: 'customer-B', vulnerableStatusCode: 200, fixedControlStatusCode: 403 });
    expect(findings.find((finding) => finding.status === 'LIKELY')?.evidence[0]?.kind).toBe('static-analysis');
    expect(findings.find((finding) => finding.status === 'NOT_REPRODUCED')?.evidence[0]?.kind).toBe('browser-observation');
    expect(findings.filter((finding) => finding.cweId === 'CWE-89' || finding.cweId === 'CWE-79').every((finding) => finding.owaspCategory === 'A05: Injection')).toBe(true);
    expect(findings.filter((finding) => finding.cweId === 'CWE-942' || finding.cweId === 'CWE-1004').every((finding) => finding.owaspCategory === 'A02: Security Misconfiguration')).toBe(true);
  });

  it('creates metadata-only projects without copying demo discovery or findings', async () => {
    const api = client();
    const result = await api.createProject(validInput);
    expect(result).toMatchObject({ name: validInput.name, languages: [], mode: 'black-box', dataSource: 'project-input' });
    expect(await api.getFindings(result.id)).toEqual([]);
    await expect(api.getDiscovery(result.id)).rejects.toMatchObject({ code: 'DISCOVERY_UNAVAILABLE' });
    await expect(api.getScan(result.id)).rejects.toMatchObject({ code: 'SCAN_UNAVAILABLE' });
    await expect(api.getFinding(result.id, 'finding-idor')).rejects.toMatchObject({ code: 'FINDING_NOT_FOUND' });
  });

  it('loads supplied discovery without changing its provenance', async () => {
    const api = client();
    const discovery = discoveryAt(validInput.repositoryPath);
    const result = await api.createProject(validInput, discovery);
    expect(result).toMatchObject({ languages: discovery.languages, mode: discovery.mode, dataSource: 'saved-discovery' });
    expect(await api.getDiscovery(result.id)).toEqual(discovery);
    expect(await api.getFindings(result.id)).toEqual([]);
  });

  it('imports saved discovery into a project after setup', async () => {
    const api = client();
    const result = await api.createProject(validInput);
    const discovery = discoveryAt(`${validInput.repositoryPath}/`);
    expect(await api.importDiscovery(result.id, discovery)).toMatchObject({ dataSource: 'saved-discovery', languages: discovery.languages });
    expect(await api.getDiscovery(result.id)).toEqual(discovery);
    await expect(api.getScan(result.id)).rejects.toMatchObject({ code: 'SCAN_UNAVAILABLE' });
  });

  it('rejects mismatched repository snapshots when creating or importing', async () => {
    const api = client();
    await expect(api.createProject(validInput, demoDiscovery)).rejects.toMatchObject({ code: 'INVALID_DISCOVERY' });
    expect(await api.listProjects()).toHaveLength(1);
    const result = await api.createProject(validInput);
    await expect(api.importDiscovery(result.id, demoDiscovery)).rejects.toMatchObject({ code: 'INVALID_DISCOVERY' });
    expect((await api.getProject(result.id)).dataSource).toBe('project-input');
    await expect(api.getDiscovery(result.id)).rejects.toMatchObject({ code: 'DISCOVERY_UNAVAILABLE' });
  });

  it('keeps returned data isolated from client state and resets between instances', async () => {
    const api = client();
    const projects = await api.listProjects();
    (projects[0]!.allowedOrigins as string[]).push('https://other.example.test');
    expect((await api.getProject('demo-shop')).allowedOrigins).toEqual(['http://localhost:3000']);
    const discovery = await api.getDiscovery('demo-shop');
    (discovery.languages as string[]).push('pretend-language');
    expect((await api.getDiscovery('demo-shop')).languages).toEqual(demoDiscovery.languages);
    await api.createProject(validInput);
    expect(await api.listProjects()).toHaveLength(2);
    expect(await client().listProjects()).toHaveLength(1);
  });

  it('rejects invalid input, invalid discovery, unknown IDs, and transport failures', async () => {
    const api = client();
    await expect(api.createProject({ ...validInput, allowedOrigins: [] })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(api.createProject(validInput, {} as DiscoveryResult)).rejects.toMatchObject({ code: 'INVALID_DISCOVERY' });
    await expect(api.getProject('missing-secret')).rejects.toMatchObject({ code: 'PROJECT_NOT_FOUND' });
    await expect(api.getFinding('demo-shop', 'missing-secret')).rejects.toMatchObject({ code: 'FINDING_NOT_FOUND' });
    const failing = createFixtureClient({ delayMs: 0, failMethods: ['listProjects'] });
    await expect(failing.listProjects()).rejects.toMatchObject({ code: 'CLIENT_UNAVAILABLE', message: 'Project data could not be loaded. Try again.' });
  });

  it('exposes browser workflow records, queries workflow details, and runs workflows', async () => {
    const api = client();
    const workflows = await api.getWorkflows('demo-shop');
    expect(workflows).toHaveLength(5);
    expect(workflows[0]!.id).toBe('wf-alice-orders');
    expect(workflows[0]!.session?.personaId).toBe('alice');
    expect(workflows[0]!.network.length).toBeGreaterThan(0);
    expect(workflows[0]!.endpoints.length).toBeGreaterThan(0);

    const single = await api.getWorkflow('demo-shop', 'wf-alice-orders');
    expect(single.goal).toContain('Alice');

    await expect(api.getWorkflow('demo-shop', 'missing-wf')).rejects.toMatchObject({ code: 'WORKFLOW_NOT_FOUND' });

    const project = await api.createProject(validInput);
    const ran = await api.runWorkflow(project.id, { goal: 'Test workflow run', identityId: 'alice' });
    expect(ran.outcome).toBe('COMPLETED');
    expect(ran.goal).toBe('Test workflow run');

    const projectWorkflows = await api.getWorkflows(project.id);
    expect(projectWorkflows).toHaveLength(1);
    expect(projectWorkflows[0]!.id).toBe(ran.id);
  });

  it('supports deleting projects in fixture client and sends DELETE in HTTP client', async () => {
    const api = client();
    const project = await api.createProject(validInput);
    expect(await api.listProjects()).toHaveLength(2);

    await api.deleteProject(project.id);
    expect(await api.listProjects()).toHaveLength(1);
    await expect(api.getProject(project.id)).rejects.toMatchObject({ code: 'PROJECT_NOT_FOUND' });

    await expect(api.deleteProject('demo-shop')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(api.deleteProject('non-existent')).rejects.toMatchObject({ code: 'PROJECT_NOT_FOUND' });

    let requestedUrl = '';
    let requestedMethod = '';
    const http = createHttpClient(async (url, init) => {
      requestedUrl = String(url);
      requestedMethod = init?.method ?? 'GET';
      return new Response(JSON.stringify({ ok: true, data: { success: true } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });
    await http.deleteProject('proj-123');
    expect(requestedUrl).toBe('/api/projects/proj-123');
    expect(requestedMethod).toBe('DELETE');
  });
});
