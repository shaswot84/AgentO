import { useEffect, useRef, useState } from 'react';
import type { Evidence } from '@agento/core';
import type { ApplicationSecurityModel, ModelEndpoint, ModelFact } from '@agento/security-model';
import type { AgentOClient, ProjectSummary, SecurityModelSnapshot } from './client/types';

const date = (value: string | null) => value ? new Date(value).toLocaleString() : 'No observations yet';
const sources = (endpoint: ModelEndpoint) => [...new Set(endpoint.observations.map(item => item.source))];
const conflict = (model: ApplicationSecurityModel, endpoint: ModelEndpoint) => model.diagnostics.some(item =>
  item.code.startsWith('conflicting-') && item.entityIds.some(id => id === endpoint.id || endpoint.aliases.includes(id)));

export function SecurityModelView({ client, project }: { client: AgentOClient; project: ProjectSummary }) {
  const [revision, setRevision] = useState(0);
  const [snapshot, setSnapshot] = useState<SecurityModelSnapshot>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [query, setQuery] = useState('');
  const [origin, setOrigin] = useState('');
  const [method, setMethod] = useState('');
  const [authentication, setAuthentication] = useState('');
  const [role, setRole] = useState('');
  const [source, setSource] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const [evidenceId, setEvidenceId] = useState('');
  const evidenceHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    let active = true;
    setLoading(true); setError(false); setSnapshot(undefined);
    void client.getSecurityModel(project.id).then(value => {
      if (active) { setSnapshot(value); setLoading(false); }
    }).catch(() => { if (active) { setError(true); setLoading(false); } });
    return () => { active = false; };
  }, [client, project.id, revision]);
  const refresh = () => setRevision(value => value + 1);
  if (loading) return <div className="loading-state" role="status"><span className="spinner" aria-hidden="true" />Loading application model…</div>;
  if (error || !snapshot) return <section className="surface"><div className="error-state" role="alert"><h2>Application model could not be loaded</h2><p>Check the local workspace service and try again.</p><button type="button" className="button secondary" onClick={refresh}>Try again</button></div></section>;
  const model = snapshot.model;
  const filtered = model.endpoints.filter(endpoint => {
    const searchable = `${endpoint.method} ${endpoint.origin}${endpoint.path} ${endpoint.roles.join(' ')} ${model.sourceHandlers
      .filter(item => item.endpointId === endpoint.id).map(item => `${item.source.file} ${item.source.symbol ?? ''}`).join(' ')}`;
    return searchable.toLowerCase().includes(query.toLowerCase()) && (!origin || endpoint.origin === origin)
      && (!method || endpoint.method === method) && (!authentication || endpoint.authentication === authentication)
      && (!role || endpoint.roles.includes(role)) && (!source || sources(endpoint).some(value => value === source));
  });
  const selected = filtered.find(item => item.id === selectedId) ?? filtered[0];
  const selectedEvidence = model.evidence.find(item => item.id === evidenceId)
    ?? model.evidence.find(item => selected?.evidenceIds.includes(item.id)) ?? model.evidence[0];
  function showEvidence(id: string) {
    setEvidenceId(id);
    requestAnimationFrame(() => { evidenceHeading.current?.focus(); evidenceHeading.current?.scrollIntoView({ block: 'nearest' }); });
  }
  const factGroups: readonly [string, readonly ModelFact[]][] = [
    ['Resource types', model.resourceTypes], ['Observed ownership', model.observedOwnership],
    ['Data-flow candidates', model.dataFlows], ['Database operations', model.databaseOperations],
    ['Cookies', model.cookies], ['CORS configuration', model.corsConfigurations],
  ];
  return <div className="model-view">
    {snapshot.sourceType === 'demo-fixture' && <div className="fixture-banner" role="note"><p><strong>Synthetic application model.</strong> These observations illustrate the interface. No live tests were run.</p></div>}
    <div className="model-status"><div><span className={`badge model-state-${snapshot.state}`}>{snapshot.state === 'ready' ? 'Observations available' : snapshot.state === 'partial' ? 'Partial coverage' : snapshot.state === 'stale' ? 'Older source snapshot' : 'Awaiting observations'}</span><p>Updated {date(snapshot.updatedAt)} · Observations do not establish a vulnerability verdict.</p></div><button type="button" className="button secondary" onClick={refresh}>Refresh model</button></div>
    <div className="metric-grid">{[['Components', model.components.length], ['Endpoints', model.endpoints.length], ['Identities', model.identities.length], ['Resources', model.resources.length]].map(([label, value]) =>
      <div className="metric" key={label}><div className="metric-label">{label}</div><div className="metric-value">{value}</div></div>)}</div>
    {(snapshot.diagnostics.length > 0 || model.diagnostics.length > 0) && <section className="surface model-coverage" aria-label="Coverage and conflicts"><h2>Coverage & conflicts</h2><ul>{snapshot.diagnostics.map((item, index) => <li key={`${item.code}-${index}`}>{item.message}</li>)}{model.diagnostics.map((item, index) => <li key={`${item.code}-${index}`}><strong>{item.code.replaceAll('-', ' ')}</strong><span className="mono"> · {item.entityIds.join(', ')}</span></li>)}</ul></section>}
    {snapshot.state === 'empty' && <section className="surface"><div className="empty-state"><h2>No application observations yet</h2><p>Run a static scan to collect source context, or a browser workflow to observe application behavior. Discovery alone describes the stack.</p><div className="model-actions"><a className="button secondary" href="#scan">Open scan progress</a><a className="button secondary" href="#workflows">Open workflows</a></div></div></section>}
    <details className="surface model-inventory"><summary>Components, identities & resources</summary><div className="model-inventory-grid"><div><h3>Components</h3>{model.components.length ? <ul>{model.components.map(item => <li key={item.id}>{item.name} <span className="muted">· {item.kind}</span></li>)}</ul> : <p>None observed.</p>}</div><div><h3>Identities & roles</h3>{model.identities.length ? <ul>{model.identities.map(item => <li key={item.id}>{item.label} <span className="muted">· {item.roles.join(', ') || 'No declared roles'}</span></li>)}</ul> : <p>No identity declarations retained.</p>}<p>{model.userRoles.length} declared role association(s).</p></div><div><h3>Resources</h3>{model.resources.length ? <ul>{model.resources.map(item => <li key={item.id}>{item.type} <span className="mono">{item.externalKey}</span></li>)}</ul> : <p>None observed. Viewing a resource does not establish ownership.</p>}</div></div></details>
    <section className="surface" aria-label="Endpoint explorer"><div className="surface-heading"><div><h2>Endpoint explorer</h2><p className="surface-description">Canonical routes with source and runtime provenance.</p></div><span className="muted" role="status">{filtered.length} of {model.endpoints.length} endpoints</span></div>
      <div className="toolbar model-filters"><label className="search-field"><span className="screen-reader-only">Search endpoints</span><input placeholder="Search routes, handlers, or roles…" value={query} onChange={event => setQuery(event.target.value)} /></label>
        <Filter label="Origin" value={origin} onChange={setOrigin} options={[...new Set(model.endpoints.map(item => item.origin))]} />
        <Filter label="Method" value={method} onChange={setMethod} options={[...new Set(model.endpoints.map(item => item.method))]} />
        <Filter label="Authentication" value={authentication} onChange={setAuthentication} options={['required', 'optional', 'unknown']} />
        <Filter label="Role" value={role} onChange={setRole} options={model.userRoles.map(item => item.name)} />
        <Filter label="Observation source" value={source} onChange={setSource} options={['source', 'browser', 'runtime', 'declared']} />
        <button className="text-button" onClick={() => { setQuery(''); setOrigin(''); setMethod(''); setAuthentication(''); setRole(''); setSource(''); }}>Clear filters</button>
      </div>
      <div className="table-scroll"><table className="data-table model-endpoints"><caption className="screen-reader-only">Application endpoints; select a route to inspect its evidence.</caption><thead><tr><th>Route</th><th>Authentication</th><th>Roles</th><th>Observed in</th></tr></thead><tbody>{filtered.map(endpoint => <tr key={endpoint.id} className={selected?.id === endpoint.id ? 'model-selected' : ''}><td><button type="button" className="model-route" aria-pressed={selected?.id === endpoint.id} onClick={() => { setSelectedId(endpoint.id); setEvidenceId(''); }}><strong className="mono">{endpoint.method} {endpoint.path}</strong><span>{endpoint.origin}</span></button></td><td>{endpoint.authentication}{conflict(model, endpoint) && <span className="badge model-state-stale">Conflicting claims</span>}</td><td>{endpoint.roles.join(', ') || 'Unknown'}</td><td><div className="tag-list">{sources(endpoint).map(value => <span className="tag" key={value}>{value}</span>)}</div></td></tr>)}</tbody></table></div>
      {!filtered.length && <div className="empty-state"><h3>{model.endpoints.length ? 'No matching endpoints' : 'No endpoints observed'}</h3><p>{model.endpoints.length ? 'Adjust the search or filters to explore other routes.' : 'Source extraction and completed runtime requests contribute routes.'}</p></div>}
    </section>
    {selected && <section className="surface model-detail" aria-label="Endpoint details"><div className="surface-heading"><div><h2 className="mono">{selected.method} {selected.path}</h2><p className="surface-description">{selected.origin}</p></div><span className="badge">{selected.aliases.length} provider alias(es)</span></div><div className="model-detail-grid">
      <div><h3>Authentication & roles</h3>{model.authenticationRequirements.filter(item => item.endpointId === selected.id).map((item, index) => <div className="model-claim" key={index}><span className="tag">{item.source}</span> {item.requirement} · {item.roles.join(', ') || 'Roles unknown'}<EvidenceLinks ids={item.evidenceIds} onSelect={showEvidence} /></div>)}<p>Session success does not establish endpoint authorization.</p></div>
      <div><h3>Parameters</h3>{model.parameters.filter(item => item.endpointId === selected.id).map(item => <div className="model-claim" key={`${item.location}:${item.name}`}><span className="mono">{item.name}</span> · {item.location} · {item.required === null ? 'Requiredness unknown' : item.required ? 'Required' : 'Optional'}<EvidenceLinks ids={item.evidenceIds} onSelect={showEvidence} /></div>)}{!selected.parameters.length && <p>No parameters observed.</p>}</div>
      <div><h3>Source handlers</h3>{model.sourceHandlers.filter(item => item.endpointId === selected.id).map((item, index) => <div className="model-claim" key={index}><span className="mono">{item.source.symbol ? `${item.source.symbol} · ` : ''}{item.source.file}:{item.source.startLine}</span><EvidenceLinks ids={item.evidenceIds} onSelect={showEvidence} /></div>)}{!model.sourceHandlers.some(item => item.endpointId === selected.id) && <p>No handler location retained.</p>}</div>
      {factGroups.map(([title, facts]) => <FactGroup key={title} title={title} facts={facts.filter(item => item.endpointIds.includes(selected.id))} onEvidence={showEvidence} />)}
      <details className="model-aliases"><summary>Original endpoint observations ({selected.observations.length})</summary><pre>{JSON.stringify(selected.observations, null, 2)}</pre></details>
    </div></section>}
    {factGroups.some(([, facts]) => facts.some(item => !item.endpointIds.length)) && <details className="surface model-inventory"><summary>Project configuration without an endpoint association</summary><div className="model-detail-grid">{factGroups.map(([title, facts]) => <FactGroup key={title} title={title} facts={facts.filter(item => !item.endpointIds.length)} onEvidence={showEvidence} />)}</div></details>}
    <section className="surface model-evidence" aria-label="Model evidence"><div className="surface-heading"><div><h2 ref={evidenceHeading} tabIndex={-1}>Original evidence</h2><p className="surface-description">{model.evidence.length} records · {model.runtimeObservations.length} runtime observations · {model.signals.length} candidate signals</p></div></div><div className="surface-body"><label htmlFor="model-evidence-record">Evidence record</label><select id="model-evidence-record" value={selectedEvidence?.id ?? ''} disabled={!model.evidence.length} onChange={event => setEvidenceId(event.target.value)}>{!model.evidence.length && <option value="">No evidence retained</option>}{model.evidence.map(item => <option key={item.id} value={item.id}>{item.id} · {item.kind}</option>)}</select>{selectedEvidence && <EvidenceDetails evidence={selectedEvidence} model={model} />}</div></section>
    <details className="surface model-inventory"><summary>Contributing runs ({snapshot.inputs.length})</summary><div className="table-scroll"><table className="data-table"><thead><tr><th>Run</th><th>Source</th><th>Captured</th><th>Outcome</th><th>Included</th></tr></thead><tbody>{snapshot.inputs.map(item => <tr key={`${item.source}:${item.runId}`}><td className="mono">{item.runId}</td><td>{item.source}</td><td>{date(item.capturedAt)}</td><td>{item.outcome}</td><td>{item.included ? 'Yes' : 'No · review diagnostics'}</td></tr>)}</tbody></table></div></details>
  </div>;
}

function Filter({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: readonly string[] }) {
  return <label className="model-filter"><span>{label}</span><select aria-label={`Filter endpoints by ${label.toLowerCase()}`} value={value} onChange={event => onChange(event.target.value)}><option value="">All</option>{[...options].sort().map(option => <option key={option} value={option}>{option}</option>)}</select></label>;
}
function EvidenceLinks({ ids, onSelect }: { ids: readonly string[]; onSelect: (id: string) => void }) {
  if (!ids.length) return null;
  const links = <div className="model-evidence-links">{ids.map((id, index) => <button type="button" className="text-button" key={id} title={id} onClick={() => onSelect(id)} aria-label={`Inspect evidence ${id}`}>Evidence {index + 1}</button>)}</div>;
  return ids.length === 1 ? links : <details className="model-evidence-list"><summary>{ids.length} evidence records</summary>{links}</details>;
}
function FactGroup({ title, facts, onEvidence }: { title: string; facts: readonly ModelFact[]; onEvidence: (id: string) => void }) {
  return <div className="model-fact-group"><h3>{title}</h3>{facts.length ? facts.map(fact => <div className="model-claim" key={fact.id}><span className="tag">{fact.source}</span><details><summary>{factSummary(fact)}</summary><pre>{JSON.stringify(fact.details, null, 2)}</pre></details><EvidenceLinks ids={fact.evidenceIds} onSelect={onEvidence} /></div>) : <p>No observations retained.</p>}</div>;
}
function factSummary(fact: ModelFact): string {
  const details = fact.details;
  if (fact.kind === 'ownership') return `${details.resourceId} → ${details.ownerIdentityId}`;
  if (fact.kind === 'resource-type') return `${details.type ?? 'Resource type'} · ${details.externalKey ?? ''}`;
  if (fact.kind === 'database-operation') return `${details.operation ?? 'Unknown operation'} · ${Array.isArray(details.tables) ? details.tables.join(', ') : 'Tables unknown'}`;
  if (fact.kind === 'cookie') return `Cookie ${typeof details.name === 'string' ? details.name : 'configuration'} · observed metadata`;
  if (fact.kind === 'data-flow') return 'Source → sink candidate · runtime verification required';
  return String(details.observation ?? 'CORS response configuration');
}
function EvidenceDetails({ evidence, model }: { evidence: Evidence; model: ApplicationSecurityModel }) {
  const endpoint = evidence.endpointId ? model.endpoints.find(item => item.id === model.endpointAliases[evidence.endpointId!]) : undefined;
  return <div className="model-evidence-details"><p>{evidence.summary}</p><dl className="definition-grid"><div className="definition"><dt>Producer</dt><dd>{evidence.producerId}</dd></div><div className="definition"><dt>Captured</dt><dd>{date(evidence.capturedAt)}</dd></div><div className="definition"><dt>Source location</dt><dd className="mono">{evidence.source ? `${evidence.source.file}:${evidence.source.startLine}` : 'No source location'}</dd></div><div className="definition"><dt>Identity</dt><dd>{evidence.identityId ?? 'Unattributed'}</dd></div><div className="definition"><dt>Original endpoint ID</dt><dd className="mono">{evidence.endpointId ?? 'Project observation'}</dd></div><div className="definition"><dt>Canonical route</dt><dd className="mono">{endpoint ? `${endpoint.method} ${endpoint.path}` : 'No endpoint association'}</dd></div></dl><pre>{JSON.stringify(evidence.facts, null, 2)}</pre></div>;
}
