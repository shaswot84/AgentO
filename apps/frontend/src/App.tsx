import { useEffect, useRef, useState } from 'react';
import type { DependencyList, FormEvent, ReactNode } from 'react';
import type { FindingStatus } from '@agento/core';
import type { DiscoveryResult } from '@agento/discovery';
import { AgentOClientError, parseSavedDiscovery, validateProjectInput } from './client';
import type { AgentOClient, FindingDetail, ProjectInput, ProjectInputErrors, ProjectSummary } from './client';

type View = 'projects' | 'discovery' | 'scan' | 'findings';
const views: { id: View; label: string; icon: IconName }[] = [
  { id: 'projects', label: 'Projects', icon: 'folder' },
  { id: 'discovery', label: 'Discovery', icon: 'compass' },
  { id: 'scan', label: 'Scan progress', icon: 'activity' },
  { id: 'findings', label: 'Findings', icon: 'shield' },
];
const statusLabels: Record<FindingStatus, string> = {
  HYPOTHESIS: 'Hypothesis', LIKELY: 'Likely', CONFIRMED: 'Confirmed',
  NOT_REPRODUCED: 'Not reproduced', REJECTED: 'Rejected',
};
type IconName = 'folder' | 'compass' | 'activity' | 'shield' | 'plus' | 'arrow' | 'search' | 'info' | 'check' | 'close' | 'file';
const iconPaths: Record<IconName, string> = {
  folder: 'M3 7V5h6l2 2h10v13H3V7Z',
  compass: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm4 5-3 5-5 3 3-5 5-3Z',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  shield: 'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Zm-4 9 3 3 5-6',
  plus: 'M12 5v14M5 12h14', arrow: 'M5 12h14m-5-5 5 5-5 5',
  search: 'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm5 12 6 6',
  info: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 8v6m0-10v1',
  check: 'm5 12 4 4 10-10', close: 'm6 6 12 12M6 18 18 6',
  file: 'M5 3h9l5 5v13H5V3Zm9 0v6h5M9 13h6m-6 4h6',
};
function Icon({ name }: { name: IconName }) {
  return <svg aria-hidden="true" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round"><path d={iconPaths[name]} /></svg>;
}
function ModeBadge({ mode }: { mode: ProjectSummary['mode'] }) {
  return <span className={`badge mode-${mode}`}>{mode === 'code-aware' ? 'Code-aware' : 'Black-box'}</span>;
}
function FindingBadge({ status }: { status: FindingStatus }) {
  return <span className={`badge status-${status.toLowerCase()}`}>{statusLabels[status]}</span>;
}
function Panel({ title, description, children, extra }: { title: string; description?: string; children: ReactNode; extra?: ReactNode }) {
  return <section className="surface"><div className="surface-heading"><div><h2 className="surface-title">{title}</h2>{description && <p className="surface-description">{description}</p>}</div>{extra}</div>{children}</section>;
}
function Metric({ label, value, detail, icon }: { label: string; value: ReactNode; detail: string; icon: IconName }) {
  return <div className="metric"><div className="metric-label"><Icon name={icon} />{label}</div><div className="metric-value">{value}</div><p className="metric-detail">{detail}</p></div>;
}
function Empty({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="empty-state"><Icon name="folder" /><h2>{title}</h2><p>{children}</p>{action}</div>;
}
function Loading() { return <div className="loading-state" role="status"><span className="spinner" aria-hidden="true" />Loading project data…</div>; }
function ErrorState({ retry }: { retry: () => void }) {
  return <div className="error-state" role="alert"><Icon name="info" /><h2>This view could not be loaded</h2><p>Try again to reconnect to the workspace client.</p><button className="button secondary" onClick={retry}>Try again</button></div>;
}
function FixtureNotice({ mixed = false }: { mixed?: boolean }) {
  return <div className="fixture-banner"><Icon name="info" /><p><strong>Demo data, clearly marked.</strong> {mixed ? 'Demo entries use fixture data and synthetic evidence. No tests were run to create those entries.' : 'Scan progress, findings, and evidence are fixtures. No security tests have run.'}</p></div>;
}
function useRequest<T>(load: () => Promise<T>, dependencies: DependencyList) {
  const loadRef = useRef(load);
  loadRef.current = load;
  const [retryToken, setRetryToken] = useState(0);
  const [state, setState] = useState<{ data: T | undefined; error: unknown; loading: boolean }>({ data: undefined, error: null, loading: true });
  useEffect(() => {
    let active = true;
    setState({ data: undefined, error: null, loading: true });
    void loadRef.current().then(data => { if (active) setState({ data, error: null, loading: false }); })
      .catch(error => { if (active) setState({ data: undefined, error, loading: false }); });
    return () => { active = false; };
  }, [...dependencies, retryToken]);
  return { ...state, retry: () => setRetryToken(token => token + 1) };
}
function currentView(): View {
  const hash = window.location.hash.slice(1);
  return views.some(view => view.id === hash) ? hash as View : 'projects';
}

export function App({ client }: { client: AgentOClient }) {
  const [view, setView] = useState<View>(currentView);
  const [revision, setRevision] = useState(0);
  const [selectedId, setSelectedId] = useState('demo-shop');
  const [newProjectOpen, setNewProjectOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [notification, setNotification] = useState('');
  const projectsState = useRequest(() => client.listProjects(), [client, revision]);
  const projects = projectsState.data ?? [];
  const selected = projects.find(project => project.id === selectedId) ?? projects[0];

  useEffect(() => {
    const changed = () => { setView(currentView()); };
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, []);
  function navigate(next: View) { setView(next); window.location.hash = next; setNotification(''); }
  function openProject(project: ProjectSummary) { setSelectedId(project.id); navigate('discovery'); }
  function saved(project: ProjectSummary) {
    setSelectedId(project.id); setRevision(value => value + 1); setNewProjectOpen(false); setImportOpen(false);
    navigate('discovery'); setNotification('Project saved for this session. Reloading resets the workspace.');
  }

  async function rescanSelected() {
    if (!selected) return;
    setRescanning(true);
    try {
      const res = await fetch('/api/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repositoryPath: selected.repositoryPath }),
      });
      const body = (await res.json()) as { ok?: boolean; data?: unknown; error?: string };
      if (!body.ok) throw new Error(body.error || 'Discovery failed');
      const updated = await client.importDiscovery(selected.id, body.data as DiscoveryResult);
      setRevision(value => value + 1);
      setNotification(`Repository re-scanned successfully: ${updated.name} (${updated.mode} mode)`);
    } catch (err: unknown) {
      setNotification(`Re-scan failed: ${err instanceof Error ? err.message : 'Discovery service unavailable'}. Use Import discovery to load saved JSON.`);
    } finally {
      setRescanning(false);
    }
  }

  const heading = {
    projects: { eyebrow: 'YOUR WORKSPACE', title: 'Security starts with context.', subtitle: 'A clear view of your applications, their stack, and the evidence that matters.' },
    discovery: { eyebrow: 'PROJECT INTELLIGENCE', title: 'Know your application.', subtitle: 'Repository facts, probable middleware, and the capabilities available to this project.' },
    scan: { eyebrow: 'FROM SIGNAL TO PROOF', title: 'Follow the investigation.', subtitle: 'Explore how a security signal moves through a test plan, evidence, and a verdict.' },
    findings: { eyebrow: 'EVIDENCE, NOT ASSUMPTIONS', title: 'Every finding has a story.', subtitle: 'Inspect the hypothesis, the verdict, and the evidence that connects them.' },
  }[view];

  return <div className="app-shell">
    <a className="skip-link" href="#main-content" onClick={event => { event.preventDefault(); document.getElementById('main-content')?.focus(); }}>Skip to content</a>
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="m4 20 8-16 8 16M8 14h8" /></svg></div><div><div className="brand-name">AgentO<span style={{ color: '#ef805d' }}>.</span></div><div className="brand-caption">Find the proof.</div></div></div>
      <nav className="nav" aria-label="Main navigation">{views.map(item => <a key={item.id} href={`#${item.id}`} className={`nav-item ${view === item.id ? 'active' : ''}`} aria-current={view === item.id ? 'page' : undefined} onClick={() => navigate(item.id)}><span className="nav-icon"><Icon name={item.icon} /></span><span className="nav-label">{item.label}</span>{item.id === 'projects' && <span className="nav-count">{projects.length}</span>}</a>)}</nav>
      <div className="sidebar-footer"><div className="section-label">WORKSPACE STATUS</div><strong>Local preview</strong><p>Projects stay in this session.<br />Execution APIs are not connected.</p></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><div className="breadcrumb"><span>Workspace</span><span aria-hidden="true">/</span><strong>{views.find(item => item.id === view)?.label}</strong></div><div className="topbar-status">{view !== 'projects' && projects.length > 0 && <><label className="screen-reader-only" htmlFor="project-picker">Selected project</label><select id="project-picker" className="project-picker" value={selected?.id ?? ''} onChange={event => { setSelectedId(event.target.value); setNotification(''); }}>{projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}</select></>}<span>Local workspace</span><div className="avatar" aria-hidden="true">AO</div></div></header>
      <main id="main-content" className="main-content" tabIndex={-1}>
        <div className="page-heading"><div><div className="eyebrow">{heading.eyebrow}</div><h1>{heading.title}</h1><p>{heading.subtitle}</p></div><div className="heading-actions">{view === 'discovery' && selected && <><button type="button" className="button secondary" onClick={() => void rescanSelected()} disabled={rescanning}><Icon name="compass" />{rescanning ? 'Re-scanning…' : 'Re-scan repository'}</button><button className="button secondary" onClick={() => setImportOpen(true)}><Icon name="file" />Import discovery</button></>}<button className="button primary" onClick={() => setNewProjectOpen(true)}><Icon name="plus" />New project</button></div></div>
        {notification && <div className="notice success" role="status"><Icon name="check" /><p>{notification}</p></div>}
        {projectsState.loading ? <Loading /> : projectsState.error ? <ErrorState retry={projectsState.retry} /> : view === 'projects' ? <ProjectsView projects={projects} onSelect={openProject} onCreate={() => setNewProjectOpen(true)} /> : selected ? <>
          {view === 'discovery' && <DiscoveryView client={client} project={selected} revision={revision} onImport={() => setImportOpen(true)} onRescan={() => void rescanSelected()} rescanning={rescanning} />}
          {view === 'scan' && <ScanView key={selected.id} client={client} project={selected} onDemo={() => setSelectedId('demo-shop')} />}
          {view === 'findings' && <FindingsView key={selected.id} client={client} project={selected} onDemo={() => setSelectedId('demo-shop')} />}
        </> : <Panel title="Project workspace"><Empty title="Choose your first project" action={<button className="button primary" onClick={() => setNewProjectOpen(true)}>New project</button>}>Configure a repository and target to begin organizing its discovery results.</Empty></Panel>}
      </main>
    </div>
    {newProjectOpen && <ProjectDialog client={client} onClose={() => setNewProjectOpen(false)} onSaved={saved} />}
    {importOpen && selected && <ImportDialog client={client} project={selected} onClose={() => setImportOpen(false)} onSaved={saved} />}
  </div>;
}

function ProjectsView({ projects, onSelect, onCreate }: { projects: readonly ProjectSummary[]; onSelect: (project: ProjectSummary) => void; onCreate: () => void }) {
  const [query, setQuery] = useState('');
  const filtered = projects.filter(project => `${project.name} ${project.baseUrl} ${project.repositoryPath}`.toLowerCase().includes(query.toLowerCase()));
  return <><div className="metric-grid">
    <Metric label="Projects" value={projects.length.toString().padStart(2, '0')} detail="In this workspace session" icon="folder" />
    <Metric label="Discovery attached" value={projects.filter(project => project.dataSource !== 'project-input').length.toString().padStart(2, '0')} detail="Saved repository snapshots" icon="compass" />
    <Metric label="Code-aware ready" value={projects.filter(project => project.mode === 'code-aware').length.toString().padStart(2, '0')} detail="Requires a compatible adapter" icon="shield" />
    <Metric label="Live scans" value="00" detail="Execution APIs are not connected" icon="activity" />
  </div><Panel title="Your projects" description="Select an application to explore its context." extra={<span className="badge neutral">{projects.length} project{projects.length === 1 ? '' : 's'}</span>}>
    <div className="toolbar"><div className="search-field"><Icon name="search" /><label className="screen-reader-only" htmlFor="project-search">Search projects</label><input id="project-search" placeholder="Search projects or targets…" value={query} onChange={event => setQuery(event.target.value)} /></div><span className="muted">Saved in memory · resets on reload</span></div>
    {filtered.length === 0 ? <Empty title={projects.length ? 'No matching projects' : 'Your workspace is ready'} action={!projects.length && <button className="button primary" onClick={onCreate}>New project</button>}>{projects.length ? 'Try a different project name or target.' : 'Add a project to keep its discovery facts in one place.'}</Empty> : <div className="table-wrap"><table className="data-table"><caption className="screen-reader-only">Configured projects</caption><thead><tr><th scope="col">Application</th><th scope="col">Stack</th><th scope="col">Mode</th><th scope="col">Data source</th><th scope="col"><span className="screen-reader-only">Actions</span></th></tr></thead><tbody>{filtered.map(project => <tr key={project.id}><td><button className="row-link project-name" onClick={() => onSelect(project)}>{project.name}</button><p className="project-target mono">{project.baseUrl}</p></td><td><div className="tag-list">{project.languages.length ? project.languages.map(language => <span className="tag" key={language}>{language}</span>) : <span className="muted">Discovery pending</span>}</div></td><td><ModeBadge mode={project.mode} /></td><td><span className={`badge ${project.dataSource === 'demo-fixture' ? 'status-hypothesis' : 'neutral'}`}>{project.dataSource === 'demo-fixture' ? 'Demo fixture' : project.dataSource === 'saved-discovery' ? 'Saved discovery' : 'Setup only'}</span></td><td><button className="row-link" aria-label={`Open ${project.name}`} onClick={() => onSelect(project)}><Icon name="arrow" /></button></td></tr>)}</tbody></table></div>}
  </Panel><div className="split-grid" style={{ marginTop: 24 }}><Panel title="Context before testing" description="Start with what the repository can tell you."><div className="surface-body"><p className="muted">Import a saved discovery result to see your application's stack, probable middleware, and available source-analysis capabilities.</p><button className="button ghost" onClick={onCreate} style={{ marginTop: 14 }}>Configure a project <Icon name="arrow" /></button></div></Panel><Panel title="Explore the evidence workflow" description="A preview of the investigation ahead."><div className="surface-body"><p className="muted">The demo project includes all five finding states and synthetic evidence so you can explore the workflow before execution APIs arrive.</p><span className="badge status-hypothesis" style={{ marginTop: 20 }}>Demo fixtures · no tests executed</span></div></Panel></div></>;
}

function Technology({ label, values }: { label: string; values: readonly string[] }) {
  return <div className="technology-list"><span className="technology-label">{label}</span><div className="technology-value tag-list">{values.length ? values.map(value => <span key={value} className="tag">{value}</span>) : <span className="muted">Not detected</span>}</div></div>;
}
function DiscoveryView({ client, project, revision, onImport, onRescan, rescanning }: { client: AgentOClient; project: ProjectSummary; revision: number; onImport: () => void; onRescan?: () => void; rescanning?: boolean }) {
  const result = useRequest(() => client.getDiscovery(project.id), [client, project.id, revision]);
  if (result.loading) return <Loading />;
  if (result.error instanceof AgentOClientError && result.error.code === 'DISCOVERY_UNAVAILABLE') return <Panel title={project.name}><Empty title="Add your repository context" action={<div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>{onRescan && <button className="button primary" onClick={onRescan} disabled={rescanning}><Icon name="compass" />{rescanning ? 'Scanning…' : 'Run discovery'}</button>}<button className="button secondary" onClick={onImport}><Icon name="file" />Import discovery JSON</button></div>}>This project has no saved discovery result. Run discovery or import the JSON created by AgentO's repository discovery CLI.</Empty></Panel>;
  if (result.error || !result.data) return <ErrorState retry={result.retry} />;
  const data = result.data;
  return <>
    {project.dataSource === 'demo-fixture' && <div className="fixture-banner"><Icon name="info" /><p><strong>Saved demo discovery.</strong> Repository facts come from the controlled demo application. Scan results remain fixtures.</p></div>}
    <div className="metric-grid"><Metric label="Languages" value={data.languages.length} detail={data.languages.join(' / ') || 'Not detected'} icon="file" /><Metric label="Dependencies" value={data.dependencies.length} detail="Direct manifest declarations" icon="folder" /><Metric label="Source files" value={data.structure.sourceFileCount} detail="From the saved repository inventory" icon="compass" /><Metric label="Analysis mode" value={<ModeBadge mode={data.mode} />} detail={data.expressAdapterAvailable ? 'Express adapter registered' : 'Express adapter unavailable'} icon="shield" /></div>
    {!data.supportedCodeAwareMode && <div className="notice warning"><Icon name="info" /><div><h3>Black-box mode selected</h3><ul>{data.fallbackReasons.map(reason => <li key={reason}>{reason}</li>)}</ul></div></div>}
    {data.diagnostics.length > 0 && <div className="notice error" role="status"><Icon name="info" /><div><h3>Discovery needs attention</h3><ul>{data.diagnostics.map((item, index) => <li key={index}><span className="mono">{item.file}</span>: {item.message}</li>)}</ul></div></div>}
    <div className="discovery-grid"><Panel title="Application fingerprint" description={project.name}><div className="surface-body"><Technology label="Languages" values={data.languages} /><Technology label="Frameworks" values={data.frameworks} /><Technology label="Database hints" values={data.databases} /><Technology label="ORM hints" values={data.orms} /><Technology label="Authentication" values={data.authentication} /><Technology label="Auth packages" values={data.authenticationPackages} /><Technology label="Available adapters" values={data.availableAdapterIds} /></div></Panel>
    <Panel title="Project & scope" description="Declared project metadata, not testing authorization."><div className="surface-body"><dl className="definition-grid"><div className="definition"><dt>Repository</dt><dd className="mono">{project.repositoryPath}</dd></div><div className="definition"><dt>Target URL</dt><dd className="mono">{project.baseUrl}</dd></div><div className="definition"><dt>Allowed origins</dt><dd>{project.allowedOrigins.map(origin => <div className="mono" key={origin}>{origin}</div>)}</dd></div><div className="definition"><dt>Snapshot name</dt><dd>{data.name}</dd></div></dl><div className="adapter-callout"><Icon name="shield" /><div><h3>{data.expressAdapterAvailable ? 'Adapter registered' : 'Express adapter unavailable'}</h3><p>Discovery describes source support. Backend policy checks will govern actual execution.</p></div></div>{onRescan && <div style={{ marginTop: 14 }}><button type="button" className="button secondary" onClick={onRescan} disabled={rescanning}><Icon name="compass" />{rescanning ? 'Re-scanning repository…' : 'Re-scan this repository'}</button></div>}</div></Panel></div>
    <div className="stack" style={{ marginTop: 22 }}><Panel title="Middleware observations" description="Probable packages and literal header writes. These observations are not vulnerabilities.">{data.middleware.length === 0 ? <Empty title="No middleware hints">No recognized middleware was present in this saved result.</Empty> : <div className="table-wrap"><table className="data-table"><thead><tr><th scope="col">Middleware</th><th scope="col">Kind</th><th scope="col">Basis</th><th scope="col">Source</th></tr></thead><tbody>{data.middleware.map((item, index) => <tr key={index}><td className="mono">{item.name}</td><td><span className="tag">{item.kind}</span></td><td>{item.basis}</td><td className="mono">{item.file}{item.line ? `:${item.line}` : ''}</td></tr>)}</tbody></table></div>}</Panel>
    <Panel title="Repository structure" description="Visited directories and manifests from the saved inventory."><div className="surface-body"><dl className="definition-grid">{[['Source directories', data.structure.sourceDirectories], ['Test directories', data.structure.testDirectories], ['Static directories', data.structure.staticDirectories], ['All visited directories', data.structure.directories]].map(([label, values]) => <div key={label as string} className="definition"><dt>{label as string}</dt><dd className="mono">{(values as readonly string[]).join(', ') || 'None recorded'}</dd></div>)}</dl><div className="section-label" style={{ marginTop: 24 }}>MANIFEST FILES</div>{data.structure.manifests.map(manifest => <div className="file-list" key={manifest.file}><Icon name="file" /><div><span className="mono">{manifest.file}</span><p className="muted">{manifest.name ?? 'Unnamed manifest'} · Root: {manifest.directory}{manifest.workspacePatterns.length ? ` · Workspaces: ${manifest.workspacePatterns.join(', ')}` : ''}</p></div></div>)}{!data.structure.manifests.length && <p className="muted">No manifests recorded.</p>}</div></Panel>
    <Dependencies data={data} /></div>
  </>;
}
function Dependencies({ data }: { data: DiscoveryResult }) {
  const [query, setQuery] = useState('');
  const dependencies = data.dependencies.filter(item => `${item.name} ${item.kind} ${item.manifest}`.toLowerCase().includes(query.toLowerCase()));
  return <Panel title="Dependency inventory" description="Runtime, development, optional, and peer declarations retain their provenance."><div className="toolbar"><div className="search-field"><Icon name="search" /><label className="screen-reader-only" htmlFor="dependency-search">Search dependencies</label><input id="dependency-search" placeholder="Search packages…" value={query} onChange={event => setQuery(event.target.value)} /></div><span className="muted">{dependencies.length} declarations</span></div>{dependencies.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th scope="col">Package</th><th scope="col">Version</th><th scope="col">Section</th><th scope="col">Manifest</th></tr></thead><tbody>{dependencies.map((item, index) => <tr key={index}><td className="mono">{item.name}</td><td className="mono">{item.version}</td><td>{item.kind}</td><td className="mono">{item.manifest}</td></tr>)}</tbody></table></div> : <Empty title="No matching dependencies">Try a different package name or dependency section.</Empty>}</Panel>;
}

function ScanView({ client, project, onDemo }: { client: AgentOClient; project: ProjectSummary; onDemo: () => void }) {
  const result = useRequest(() => client.getScan(project.id), [client, project.id]);
  const [playing, setPlaying] = useState(false);
  const [step, setStep] = useState(0);
  const stages = result.data?.stages ?? [];
  useEffect(() => {
    if (!playing) return;
    if (step >= stages.length) { setPlaying(false); return; }
    const timer = window.setTimeout(() => setStep(value => value + 1), 650);
    return () => window.clearTimeout(timer);
  }, [playing, step, stages.length]);
  if (result.loading) return <Loading />;
  if (result.error instanceof AgentOClientError && result.error.code === 'SCAN_UNAVAILABLE') return <Panel title="Scan progress"><Empty title="No scan has run" action={<button className="button secondary" onClick={onDemo}>Explore the demo fixture</button>}>Execution APIs are not connected. Your project's setup and discovery do not create security test results.</Empty></Panel>;
  if (result.error || !result.data) return <ErrorState retry={result.retry} />;
  const fixture = result.data.source === 'demo-fixture';
  const completeCount = fixture && playing ? stages.slice(0, step).filter(stage => stage.status === 'complete').length : stages.filter(stage => stage.status === 'complete').length;
  const progress = stages.length ? Math.round(completeCount / stages.length * 100) : 0;
  const stateLabels = { pending: 'Scan pending', running: 'Scan in progress', complete: 'Scan complete', failed: 'Scan failed' };
  return <>{fixture && <FixtureNotice />}<div className="scan-layout">
    <Panel title="Investigation timeline" description={fixture ? 'A replayable demonstration of the evidence workflow.' : 'The latest progress reported by the execution service.'} extra={<span className="badge neutral">{fixture ? 'Fixture' : 'Execution result'}</span>}>
      <div className="surface-body">
        <div className="progress-summary"><h3>{fixture ? playing ? 'Playing preview' : 'Demo snapshot complete' : stateLabels[result.data.state]}</h3><span className="muted">{completeCount} / {stages.length} stages</span></div>
        <div className="progress-track" role="progressbar" aria-label={fixture ? 'Fixture workflow progress' : 'Scan workflow progress'} aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}><div className="progress-fill" style={{ width: `${progress}%` }} /></div>
        <ol className="timeline">{stages.map((stage, index) => {
          const state = stage.status === 'unavailable' || stage.status === 'failed' ? stage.status : fixture && playing ? index < step ? 'completed' : index === step ? 'active' : 'pending' : stage.status === 'complete' ? 'completed' : stage.status === 'running' ? 'active' : 'pending';
          const label = state === 'unavailable' ? 'Adapter unavailable' : state === 'failed' ? 'Stage failed' : state === 'active' ? fixture ? 'Previewing' : 'In progress' : state === 'completed' ? fixture ? 'Fixture stage complete' : 'Stage complete' : fixture ? 'Preview pending' : 'Pending';
          return <li key={stage.id} className={`timeline-item ${state}`}><span className="timeline-marker" aria-hidden="true">{state === 'completed' ? <Icon name="check" /> : ['unavailable', 'failed'].includes(state) ? '!' : index + 1}</span><div className="timeline-content"><h3>{stage.label}</h3><p>{stage.details}</p><span className="timeline-meta">{label}</span></div></li>;
        })}</ol>
        {fixture && <button className="button primary" onClick={() => { if (playing) setPlaying(false); else { setStep(0); setPlaying(true); } }}><Icon name="activity" />{playing ? 'Stop preview' : 'Replay preview'}</button>}
      </div>
    </Panel>
    <div className="stack"><Panel title={fixture ? 'What this preview shows' : 'Scan summary'}><div className="surface-body"><p className="muted">{result.data.summary}</p>{fixture && <div className="notice info" style={{ marginTop: 20, marginBottom: 0 }}><Icon name="info" /><p>Replay changes only this screen. It sends no requests to the configured target.</p></div>}</div></Panel><Panel title="Current project"><div className="surface-body"><h3>{project.name}</h3><p className="mono muted" style={{ margin: '8px 0 18px' }}>{project.baseUrl}</p><ModeBadge mode={project.mode} /></div></Panel></div>
  </div></>;
}

function FindingsView({ client, project, onDemo }: { client: AgentOClient; project: ProjectSummary; onDemo: () => void }) {
  const result = useRequest(() => client.getFindings(project.id), [client, project.id]);
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [selectedFinding, setSelectedFinding] = useState('');
  if (result.loading) return <Loading />;
  if (result.error || !result.data) return <ErrorState retry={result.retry} />;
  const all = result.data;
  if (!all.length) return <Panel title="Findings"><Empty title="No findings recorded" action={<button className="button secondary" onClick={onDemo}>Explore the demo fixture</button>}>This project has no executed tests or evidence. Importing discovery does not produce findings.</Empty></Panel>;
  const filtered = all.filter(finding => (!status || finding.status === status) && `${finding.title} ${finding.cweId} ${finding.endpoint?.path ?? ''}`.toLowerCase().includes(query.toLowerCase()));
  const selected = filtered.find(finding => finding.id === selectedFinding) ?? filtered[0];
  const fixtureOnly = all.every(finding => finding.sourceType === 'demo-fixture');
  const hasFixtures = all.some(finding => finding.sourceType === 'demo-fixture');
  return <>{hasFixtures && <FixtureNotice mixed={!fixtureOnly} />}<div className="metric-grid"><Metric label={fixtureOnly ? 'Fixture findings' : 'Findings'} value={all.length.toString().padStart(2, '0')} detail={fixtureOnly ? 'Synthetic investigation results' : 'Investigation results'} icon="shield" /><Metric label={fixtureOnly ? 'Confirmed fixtures' : 'Confirmed findings'} value={all.filter(finding => finding.status === 'CONFIRMED').length.toString().padStart(2, '0')} detail={fixtureOnly ? 'Demonstrates an evidence-backed verdict' : 'Evidence-backed verdicts'} icon="check" /><Metric label="Need investigation" value={all.filter(finding => ['HYPOTHESIS', 'LIKELY'].includes(finding.status)).length.toString().padStart(2, '0')} detail="Hypotheses and likely candidates" icon="search" /><Metric label={fixtureOnly ? 'Closed fixtures' : 'Closed findings'} value={all.filter(finding => ['NOT_REPRODUCED', 'REJECTED'].includes(finding.status)).length.toString().padStart(2, '0')} detail="Not reproduced or rejected" icon="file" /></div>
    <div className="surface" style={{ marginBottom: 20 }}><div className="toolbar"><div className="search-field"><Icon name="search" /><label className="screen-reader-only" htmlFor="finding-search">Search findings</label><input id="finding-search" placeholder="Search findings, CWE, or route…" value={query} onChange={event => setQuery(event.target.value)} /></div><label className="screen-reader-only" htmlFor="status-filter">Filter finding status</label><select className="filter-select" id="status-filter" value={status} onChange={event => setStatus(event.target.value)}><option value="">All statuses</option>{Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><span className="muted">{filtered.length} {filtered.length === 1 ? 'finding' : 'findings'}</span></div></div>
    {selected ? <div className="finding-layout"><Panel title="Investigation queue"><div className="finding-list">{filtered.map(finding => <button key={finding.id} className={`finding-item ${selected.id === finding.id ? 'selected' : ''}`} onClick={() => setSelectedFinding(finding.id)} aria-pressed={selected.id === finding.id}><span className={`badge severity-${finding.severity}`}>{finding.severity}</span><FindingBadge status={finding.status} /><h3>{finding.title}</h3><div className="mono">{finding.cweId} · {finding.endpoint?.method} {finding.endpoint?.path ?? 'Source candidate'}</div></button>)}</div></Panel><FindingDetails client={client} projectId={project.id} findingId={selected.id} /></div> : <Panel title="Investigation queue"><Empty title="No matching findings">Try a different search or select another finding status.</Empty></Panel>}
  </>;
}
function FindingDetails({ client, projectId, findingId }: { client: AgentOClient; projectId: string; findingId: string }) {
  const result = useRequest(() => client.getFinding(projectId, findingId), [client, projectId, findingId]);
  if (result.loading) return <Panel title="Finding details"><Loading /></Panel>;
  if (result.error || !result.data) return <Panel title="Finding details"><ErrorState retry={result.retry} /></Panel>;
  return <FindingDetailPanel finding={result.data} />;
}
function FindingDetailPanel({ finding }: { finding: FindingDetail }) {
  const fixture = finding.sourceType === 'demo-fixture';
  return <section className="surface finding-detail" aria-label="Selected finding"><div className="surface-heading"><div><div className="eyebrow">{finding.cweId} · {finding.owaspCategory}</div><h2>{finding.title}</h2><div className="tag-list"><FindingBadge status={finding.status} /><span className={`badge severity-${finding.severity}`}>{finding.severity} severity</span><span className="badge neutral">{finding.confidence} confidence</span></div></div></div><div className="surface-body"><div className="section-label">ROOT CAUSE{fixture ? ' · FIXTURE' : ''}</div><p>{finding.rootCause}</p><dl className="definition-grid" style={{ marginBottom: 26 }}><div className="definition"><dt>Affected endpoint</dt><dd className="mono">{finding.endpoint ? `${finding.endpoint.method} ${finding.endpoint.path}` : 'No endpoint recorded'}</dd></div><div className="definition"><dt>Source location</dt><dd className="mono">{finding.source ? `${finding.source.file}:${finding.source.startLine}` : 'No source recorded'}</dd></div></dl><div className="section-label">EVIDENCE TRAIL{fixture ? ' · SYNTHETIC' : ''}</div>{finding.evidence.map(evidence => <article className="evidence-card" key={evidence.id}><div className="evidence-header"><h3>{evidence.kind.replaceAll('-', ' ')}</h3><span className="badge neutral">{fixture ? 'Fixture evidence' : 'Recorded evidence'}</span></div><p>{evidence.summary}</p>{evidence.source && <p className="evidence-source mono">{evidence.source.file}:{evidence.source.startLine}</p>}<dl className="evidence-facts">{Object.entries(evidence.facts).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{typeof value === 'string' ? value : JSON.stringify(value)}</dd></div>)}</dl><p className="evidence-source mono">{evidence.id} · {evidence.producerId}</p></article>)}{!finding.evidence.length && <p className="muted">No evidence recorded for this finding.</p>}<div className="remediation"><div className="section-label">SUGGESTED REMEDIATION{fixture ? ' · FIXTURE' : ''}</div><p>{finding.remediation.explanation}</p>{finding.remediation.patch && <pre style={{ marginTop: 12 }}>{finding.remediation.patch}</pre>}{finding.remediation.regressionTest && <p className="muted" style={{ marginTop: 12 }}>{finding.remediation.regressionTest}</p>}</div></div></section>;
}

function Dialog({ title, description, onClose, children, busy = false }: { title: string; description: string; onClose: () => void; children: ReactNode; busy?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { const dialog = ref.current; dialog?.showModal(); return () => { dialog?.close(); }; }, []);
  return <dialog className="dialog" ref={ref} aria-labelledby="dialog-title" aria-describedby="dialog-description" onCancel={event => { if (busy) event.preventDefault(); else onClose(); }}><div className="dialog-header"><div><h2 id="dialog-title">{title}</h2><p id="dialog-description">{description}</p></div><button className="icon-button" aria-label="Close dialog" onClick={onClose} disabled={busy}><Icon name="close" /></button></div>{children}</dialog>;
}
function useSavedFile() {
  const [data, setData] = useState<DiscoveryResult | undefined>();
  const [error, setError] = useState('');
  const [fileName, setFileName] = useState('');
  const [reading, setReading] = useState(false);
  const sequence = useRef(0);
  useEffect(() => () => { sequence.current += 1; }, []);
  async function read(file: File | undefined) {
    const token = ++sequence.current;
    setData(undefined); setError(''); setFileName('');
    if (!file) { setReading(false); return undefined; }
    if (file.size > 2 * 1024 * 1024) { setReading(false); setError('Choose a discovery JSON file smaller than 2 MiB.'); return undefined; }
    setReading(true);
    try {
      const parsed = parseSavedDiscovery(JSON.parse(await file.text()) as unknown);
      if (token !== sequence.current) return undefined;
      if (!parsed.ok) { setError(parsed.error); return undefined; }
      setData(parsed.value); setFileName(file.name); return parsed.value;
    } catch { if (token === sequence.current) setError('This file is not a valid saved AgentO discovery result.'); return undefined; }
    finally { if (token === sequence.current) setReading(false); }
  }
  function setDirect(discoveryData: unknown, label = 'Local Discovery Result') {
    const parsed = parseSavedDiscovery(discoveryData);
    if (!parsed.ok) { setError(parsed.error); return undefined; }
    setData(parsed.value); setFileName(label); setError(''); return parsed.value;
  }
  return { data, error, fileName, reading, setReading, setError, read, setDirect };
}
function FileField({ saved, onRead }: { saved: ReturnType<typeof useSavedFile>; onRead: (file: File | undefined) => void }) {
  return <div className="form-field full-width"><label htmlFor="discovery-file">Saved discovery JSON</label><input id="discovery-file" className="file-input" type="file" accept="application/json,.json" aria-describedby="discovery-file-help discovery-file-error" aria-invalid={Boolean(saved.error)} onChange={event => onRead(event.target.files?.[0])} /><p id="discovery-file-help" className="help-text">Optional during setup. Import the discovery CLI's JSON output, up to 2 MiB.</p>{saved.reading && <p role="status" className="help-text">Checking discovery file…</p>}{saved.fileName && <p role="status" className="help-text">Attached: {saved.fileName} · {saved.data?.structure.sourceFileCount} source files</p>}<p id="discovery-file-error" className="field-error" role={saved.error ? 'alert' : undefined}>{saved.error}</p></div>;
}
function clientErrorMessage(error: unknown): string {
  return error instanceof AgentOClientError ? error.message : 'This operation could not be completed. Try again.';
}
function ProjectDialog({ client, onClose, onSaved }: { client: AgentOClient; onClose: () => void; onSaved: (project: ProjectSummary) => void }) {
  const [fields, setFields] = useState({ name: '', repositoryPath: '', baseUrl: 'http://localhost:3000', origins: 'http://localhost:3000' });
  const [errors, setErrors] = useState<ProjectInputErrors>({});
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [demoApps, setDemoApps] = useState<{ id: string; name: string; path: string }[]>([]);
  const saved = useSavedFile();

  useEffect(() => {
    fetch('/api/demo-apps')
      .then(res => res.json())
      .then((res: { ok?: boolean; data?: { id: string; name: string; path: string }[] }) => {
        if (res.ok && Array.isArray(res.data)) setDemoApps(res.data);
      })
      .catch(() => undefined);
  }, []);

  async function runLocalDiscovery(targetPath?: string) {
    const pathToRun = targetPath || fields.repositoryPath;
    if (!pathToRun.trim()) {
      setError('Enter a repository path to discover.');
      return;
    }
    setDiscovering(true);
    setError('');
    try {
      const res = await fetch('/api/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repositoryPath: pathToRun.trim() }),
      });
      const body = (await res.json()) as { ok?: boolean; data?: unknown; error?: string };
      if (!body.ok) throw new Error(body.error || 'Discovery failed');
      const discovery = saved.setDirect(body.data, `Auto-Discovered (${(body.data as { name?: string }).name || 'project'})`);
      if (discovery) {
        setFields(previous => ({
          ...previous,
          name: previous.name || discovery.name,
          repositoryPath: discovery.repositoryPath,
        }));
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Local discovery failed.');
    } finally {
      setDiscovering(false);
    }
  }

  function change(field: keyof typeof fields, value: string) { setFields(previous => ({ ...previous, [field]: value })); setError(''); }
  async function submit(event: FormEvent) {
    event.preventDefault();
    const input: ProjectInput = { name: fields.name, repositoryPath: fields.repositoryPath, baseUrl: fields.baseUrl, allowedOrigins: fields.origins.split('\n').map(origin => origin.trim()).filter(Boolean) };
    const nextErrors = validateProjectInput(input);
    setErrors(nextErrors); setError('');
    if (Object.keys(nextErrors).length > 0) { document.getElementById(`project-${Object.keys(nextErrors)[0]}`)?.focus(); return; }
    if (saved.error || saved.reading || discovering) return;
    setSaving(true);
    try { onSaved(await client.createProject(input, saved.data)); }
    catch (failure) { setError(clientErrorMessage(failure)); }
    finally { setSaving(false); }
  }

  return <Dialog title="New project" description="Give your application a place in the workspace." onClose={onClose} busy={saving || discovering}><form noValidate onSubmit={submit}><div className="dialog-body">
    {demoApps.length > 0 && (
      <div className="notice info" style={{ marginBottom: 16 }}>
        <Icon name="compass" />
        <div style={{ width: '100%' }}>
          <p style={{ fontWeight: 600, marginBottom: 6 }}>Quick Load Demo Project:</p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {demoApps.map(demo => (
              <button
                key={demo.id}
                type="button"
                className="button secondary"
                style={{ padding: '4px 10px', fontSize: 13 }}
                onClick={() => {
                  const isDemo2 = demo.name === 'demo-app-02';
                  setFields(prev => ({
                    ...prev,
                    name: demo.name,
                    repositoryPath: demo.path,
                    baseUrl: isDemo2 ? 'http://localhost:4000' : 'http://localhost:3000',
                    origins: isDemo2 ? 'http://localhost:4000' : 'http://localhost:3000',
                  }));
                  void runLocalDiscovery(demo.path);
                }}
              >
                {demo.name}
              </button>
            ))}
          </div>
        </div>
      </div>
    )}
    <div className="form-grid">
      <div className="form-field full-width"><label htmlFor="project-name">Project name</label><input id="project-name" placeholder="e.g. Storefront API" value={fields.name} onChange={event => change('name', event.target.value)} aria-invalid={Boolean(errors.name)} aria-describedby="name-error" autoFocus maxLength={120} /><p id="name-error" className="field-error">{errors.name}</p></div>
      <div className="form-field full-width">
        <label htmlFor="project-repositoryPath">Repository path</label>
        <div style={{ display: 'flex', gap: 8 }}>
          <input id="project-repositoryPath" placeholder="/path/to/your/repository or demo-apps/demo-app-02" value={fields.repositoryPath} onChange={event => change('repositoryPath', event.target.value)} aria-invalid={Boolean(errors.repositoryPath)} aria-describedby="repository-help repository-error" style={{ flex: 1 }} />
          <button type="button" className="button secondary" onClick={() => void runLocalDiscovery()} disabled={discovering || !fields.repositoryPath}>
            {discovering ? 'Discovering…' : 'Run Discovery'}
          </button>
        </div>
        <p id="repository-help" className="help-text">Local path on host. Click 'Run Discovery' to scan directly, or attach a JSON below.</p>
        <p id="repository-error" className="field-error">{errors.repositoryPath}</p>
      </div>
      <div className="form-field full-width"><label htmlFor="project-baseUrl">Target URL</label><input id="project-baseUrl" type="url" value={fields.baseUrl} onChange={event => change('baseUrl', event.target.value)} aria-invalid={Boolean(errors.baseUrl)} aria-describedby="target-error" /><p id="target-error" className="field-error">{errors.baseUrl}</p></div>
      <div className="form-field full-width"><label htmlFor="project-allowedOrigins">Allowed origins</label><textarea id="project-allowedOrigins" value={fields.origins} onChange={event => change('origins', event.target.value)} aria-invalid={Boolean(errors.allowedOrigins)} aria-describedby="origins-help origins-error" rows={2} /><p id="origins-help" className="help-text">One explicit origin per line. Include the target's origin.</p><p id="origins-error" className="field-error">{errors.allowedOrigins}</p></div>
      <FileField saved={saved} onRead={file => { void saved.read(file).then(discovery => { if (discovery) setFields(previous => ({ ...previous, name: previous.name || discovery.name, repositoryPath: previous.repositoryPath || discovery.repositoryPath })); }); }} />
    </div>
    {error && <div className="notice error" role="alert" style={{ marginTop: 15, marginBottom: 0 }}>{error}</div>}
    <p className="help-text" style={{ marginTop: 12 }}>Saving records setup only. It does not start live security testing.</p>
  </div>
  <div className="dialog-footer">
    <button type="button" className="button secondary" onClick={onClose} disabled={saving || discovering}>Cancel</button>
    <button className="button primary" disabled={saving || discovering || saved.reading || Boolean(saved.error)}>{saving ? 'Saving…' : 'Create project'}</button>
  </div>
  </form></Dialog>;
}
function ImportDialog({ client, project, onClose, onSaved }: { client: AgentOClient; project: ProjectSummary; onClose: () => void; onSaved: (project: ProjectSummary) => void }) {
  const saved = useSavedFile();
  const [saving, setSaving] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [error, setError] = useState('');

  async function runLocalDiscovery() {
    setDiscovering(true);
    setError('');
    try {
      const res = await fetch('/api/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repositoryPath: project.repositoryPath }),
      });
      const body = (await res.json()) as { ok?: boolean; data?: unknown; error?: string };
      if (!body.ok) throw new Error(body.error || 'Discovery failed');
      const discovery = saved.setDirect(body.data, `Auto-Discovered (${(body.data as { name?: string }).name || 'project'})`);
      if (discovery) {
        setSaving(true);
        onSaved(await client.importDiscovery(project.id, discovery));
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Local discovery failed.');
    } finally {
      setDiscovering(false);
      setSaving(false);
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault(); if (!saved.data || saved.reading || saved.error) return;
    setSaving(true); setError('');
    try { onSaved(await client.importDiscovery(project.id, saved.data)); }
    catch (failure) { setError(clientErrorMessage(failure)); }
    finally { setSaving(false); }
  }
  return <Dialog title="Import discovery" description={`Attach repository facts to ${project.name}.`} onClose={onClose} busy={saving || discovering}><form onSubmit={submit}><div className="dialog-body"><div className="notice info"><Icon name="info" /><div><p>Required repository path</p><strong className="mono">{project.repositoryPath}</strong></div></div>
  <div style={{ marginBottom: 14 }}>
    <button type="button" className="button secondary" onClick={() => void runLocalDiscovery()} disabled={discovering || saving}>
      <Icon name="compass" />
      {discovering ? 'Scanning repository…' : 'Run Discovery Directly on this Path'}
    </button>
  </div>
  <FileField saved={saved} onRead={file => { setError(''); void saved.read(file); }} />{error && <div className="notice error" role="alert">{error}</div>}<p className="help-text">This replaces the saved discovery snapshot. It does not create scan results or evidence.</p></div><div className="dialog-footer"><button type="button" className="button secondary" onClick={onClose} disabled={saving || discovering}>Cancel</button><button className="button primary" disabled={saving || discovering || saved.reading || !saved.data || Boolean(saved.error)}>{saving ? 'Importing…' : 'Import snapshot'}</button></div></form></Dialog>;
}

