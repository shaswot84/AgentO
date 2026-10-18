import { useEffect, useRef, useState } from 'react';
import type { DependencyList, FormEvent, ReactNode } from 'react';
import type { FindingStatus } from '@agento/core';
import type { DiscoveryResult } from '@agento/discovery';
import { workflowNotification, workflowProfiles } from './workflow-catalog';
import { AgentOClientError, parseSavedDiscovery, validateProjectInput } from './client';
import type { AgentOClient, BrowserWorkflowResult, FindingDetail, ObservedNetworkTraffic, ProjectInput, ProjectInputErrors, ProjectSummary } from './client';

type View = 'projects' | 'discovery' | 'workflows' | 'scan' | 'findings';
const views: { id: View; label: string; icon: IconName }[] = [
  { id: 'projects', label: 'Projects', icon: 'folder' },
  { id: 'discovery', label: 'Discovery', icon: 'compass' },
  { id: 'workflows', label: 'Workflows', icon: 'browser' },
  { id: 'scan', label: 'Scan progress', icon: 'activity' },
  { id: 'findings', label: 'Findings', icon: 'shield' },
];
const statusLabels: Record<FindingStatus, string> = {
  HYPOTHESIS: 'Hypothesis', LIKELY: 'Likely', CONFIRMED: 'Confirmed',
  NOT_REPRODUCED: 'Not reproduced', REJECTED: 'Rejected',
};
type IconName = 'folder' | 'compass' | 'activity' | 'shield' | 'plus' | 'arrow' | 'search' | 'info' | 'check' | 'close' | 'file' | 'browser' | 'network' | 'trash';
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
  browser: 'M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2Zm0 5h18M8 6.5h.01M11 6.5h.01M14 6.5h.01',
  network: 'M12 2a3 3 0 0 0-3 3c0 .54.14 1.05.39 1.49L5.49 10.4A3 3 0 0 0 5 10a3 3 0 1 0 2.83 4h8.34A3 3 0 1 0 19 12a3 3 0 0 0-.49.04l-3.9-3.91c.25-.44.39-.95.39-1.49a3 3 0 0 0-3-3Z',
  trash: 'M3 6h18m-2 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M10 11v6M14 11v6',
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
  return <div className="fixture-banner"><Icon name="info" /><p><strong>Demo workspace.</strong> {mixed ? 'Demo entries contain synthetic evidence. No tests were run for those entries.' : 'Scan progress and findings are examples. No live security tests have run.'}</p></div>;
}
function useRequest<T>(load: () => Promise<T>, dependencies: DependencyList, poll?: { interval: number; while: (data: T) => boolean }) {
  const loadRef = useRef(load);
  loadRef.current = load;
  const [retryToken, setRetryToken] = useState(0);
  const [state, setState] = useState<{ data: T | undefined; error: unknown; loading: boolean }>({ data: undefined, error: null, loading: true });
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setState({ data: undefined, error: null, loading: true });
    function refresh() {
      void loadRef.current().then(data => {
        if (!active) return;
        setState({ data, error: null, loading: false });
        if (poll?.while(data)) timer = setTimeout(refresh, poll.interval);
      }).catch(error => { if (active) setState({ data: undefined, error, loading: false }); });
    }
    refresh();
    return () => { active = false; clearTimeout(timer); };
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
  const [selectedId, setSelectedId] = useState('');
  const [newProjectOpen, setNewProjectOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [workflowRunOpen, setWorkflowRunOpen] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [projectToDelete, setProjectToDelete] = useState<ProjectSummary | null>(null);
  const [notification, setNotification] = useState<{ message: string; kind: 'success' | 'warning' | 'error' } | null>(null);
  const projectsState = useRequest(() => client.listProjects(), [client, revision, view]);
  const projects = projectsState.data ?? [];
  const selected = projects.find(project => project.id === selectedId) ?? projects[0];

  useEffect(() => {
    const changed = () => { setView(currentView()); };
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, []);
  function navigate(next: View) { setView(next); window.location.hash = next; setNotification(null); window.scrollTo({ top: 0 }); }
  function openProject(project: ProjectSummary) { setSelectedId(project.id); navigate('discovery'); }
  function saved(project: ProjectSummary) {
    setSelectedId(project.id); setRevision(value => value + 1); setNewProjectOpen(false); setImportOpen(false);
    navigate('discovery'); setNotification({ message: client.storage === 'disk' ? 'Project saved to the local workspace.' : 'Project saved for this demonstration session.', kind: 'success' });
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
      const discovery = body.data as DiscoveryResult;
      const updated = await client.importDiscovery(selected.id, discovery);
      setRevision(value => value + 1);
      setNotification(discovery.diagnostics.length
        ? { message: `Discovery saved with diagnostics for ${updated.name}. Review the issues below.`, kind: 'warning' }
        : { message: `Discovery updated for ${updated.name}. Analysis mode: ${updated.mode}.`, kind: 'success' });
    } catch (err: unknown) {
      setNotification({ message: `Re-scan failed: ${err instanceof Error ? err.message : 'Discovery service unavailable'}. Import a saved discovery JSON to continue.`, kind: 'error' });
    } finally {
      setRescanning(false);
    }
  }

  const heading = {
    projects: { eyebrow: 'APPLICATION SECURITY', title: 'Projects', subtitle: 'Your applications, their context, and the next step toward proof.' },
    discovery: { eyebrow: selected?.name ?? 'PROJECT INTELLIGENCE', title: 'Discovery', subtitle: 'Understand your stack, repository, and available analysis capabilities.' },
    workflows: { eyebrow: selected?.name ?? 'BROWSER WORKFLOW LAYER', title: 'Browser Workflows', subtitle: 'Inspect runtime user actions, discovered endpoints, session state, and intercepted network evidence.' },
    scan: { eyebrow: selected?.name ?? 'INVESTIGATION', title: 'Scan progress', subtitle: 'Follow each stage from repository context to an evidence-backed verdict.' },
    findings: { eyebrow: selected?.name ?? 'INVESTIGATION', title: 'Findings', subtitle: 'Review signals, inspect the evidence, and decide what needs attention.' },
  }[view];

  return <div className="app-shell">
    <a className="skip-link" href="#main-content" onClick={event => { event.preventDefault(); document.getElementById('main-content')?.focus(); }}>Skip to content</a>
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="m4 20 8-16 8 16M8 14h8" /></svg></div><div><div className="brand-name">AgentO<span style={{ color: '#ef805d' }}>.</span></div><div className="brand-caption">Find the proof.</div></div></div>
      <div className="nav-heading section-label">WORKSPACE</div><nav className="nav" aria-label="Main navigation">{views.map(item => <a key={item.id} href={`#${item.id}`} className={`nav-item ${view === item.id ? 'active' : ''}`} aria-current={view === item.id ? 'page' : undefined} onClick={() => navigate(item.id)}><span className="nav-icon"><Icon name={item.icon} /></span><span className="nav-label">{item.label}</span>{item.id === 'projects' && <span className="nav-count">{projects.length}</span>}</a>)}</nav>
      <div className="sidebar-footer"><div className="session-heading"><Icon name="info" /><strong>{client.storage === 'disk' ? 'Local workspace' : 'Demo workspace'}</strong></div><p>{client.storage === 'disk' ? 'Projects and results are saved on this computer. Static scans collect source candidates.' : 'Projects reset on reload.'}</p><span className="session-label">{client.storage === 'disk' ? 'LOCAL SERVICE' : 'DEMONSTRATION'}</span></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><div className="breadcrumb"><span>Workspace</span><span aria-hidden="true">/</span><strong>{views.find(item => item.id === view)?.label}</strong></div><div className="topbar-status">{view !== 'projects' && projects.length > 0 && <><label className="screen-reader-only" htmlFor="project-picker">Selected project</label><select id="project-picker" className="project-picker" value={selected?.id ?? ''} onChange={event => { setSelectedId(event.target.value); setNotification(null); }}>{projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}</select></>}<span className="local-status">{client.storage === 'disk' ? 'Local service' : 'Demo preview'}</span></div></header>
      <main id="main-content" className="main-content" tabIndex={-1}>
        <div className="page-heading"><div><div className="eyebrow">{heading.eyebrow}</div><h1>{heading.title}</h1><p>{heading.subtitle}</p></div><div className="heading-actions">{view === 'discovery' && selected && (client.storage === 'memory' || selected.dataSource !== 'demo-fixture') && <><button type="button" className="button primary" aria-label="Refresh discovery" onClick={() => void rescanSelected()} disabled={rescanning}><Icon name="compass" />{rescanning ? 'Discovering…' : 'Refresh'}</button><button className="button secondary" onClick={() => setImportOpen(true)}><Icon name="file" />Import JSON</button>{selected.id !== 'demo-shop' && <button type="button" className="button danger" onClick={() => setProjectToDelete(selected)}><Icon name="trash" />Delete project</button>}</>}{view === 'workflows' && selected && <button type="button" className="button primary" onClick={() => setWorkflowRunOpen(true)}><Icon name="plus" />Run workflow</button>}{view === 'projects' && <button className="button primary" onClick={() => setNewProjectOpen(true)}><Icon name="plus" />New project</button>}</div></div>
        {notification && <div className={`notice ${notification.kind}`} role={notification.kind === 'error' ? 'alert' : 'status'}><Icon name={notification.kind === 'success' ? 'check' : 'info'} /><p>{notification.message}</p><button className="icon-button" aria-label="Dismiss notification" onClick={() => setNotification(null)}><Icon name="close" /></button></div>}
        {projectsState.loading ? <Loading /> : projectsState.error ? <ErrorState retry={projectsState.retry} /> : view === 'projects' ? <ProjectsView projects={projects} persistent={client.storage === 'disk'} onSelect={openProject} onDelete={project => setProjectToDelete(project)} onCreate={() => setNewProjectOpen(true)} onExplore={() => { setSelectedId('demo-shop'); navigate('findings'); }} /> : selected ? <>
          {view === 'discovery' && <DiscoveryView client={client} project={selected} revision={revision} onImport={() => setImportOpen(true)} onRescan={() => void rescanSelected()} rescanning={rescanning} onDelete={() => setProjectToDelete(selected)} />}
          {view === 'workflows' && <WorkflowsView key={selected.id} client={client} project={selected} onDemo={() => setSelectedId('demo-shop')} onRunWorkflow={() => setWorkflowRunOpen(true)} />}
          {view === 'scan' && <ScanView key={selected.id} client={client} project={selected} onDemo={() => setSelectedId('demo-shop')} onNavigateWorkflows={() => navigate('workflows')} />}
          {view === 'findings' && <FindingsView key={selected.id} client={client} project={selected} onDemo={() => setSelectedId('demo-shop')} onNavigateWorkflows={() => navigate('workflows')} />}
        </> : <Panel title="Project workspace"><Empty title="Choose your first project" action={<button className="button primary" onClick={() => setNewProjectOpen(true)}>New project</button>}>Configure a repository and target to begin organizing its discovery results.</Empty></Panel>}
      </main>
    </div>
    {newProjectOpen && <ProjectDialog client={client} onClose={() => setNewProjectOpen(false)} onSaved={saved} />}
    {importOpen && selected && <ImportDialog client={client} project={selected} onClose={() => setImportOpen(false)} onSaved={saved} />}
    {workflowRunOpen && selected && <WorkflowRunDialog client={client} project={selected} onClose={() => setWorkflowRunOpen(false)} onCompleted={wf => { setSelectedId(selected.id); setRevision(value => value + 1); setNotification({ message: workflowNotification(wf), kind: wf.outcome === 'COMPLETED' ? 'success' : 'warning' }); }} />}
    {projectToDelete && <DeleteProjectDialog client={client} project={projectToDelete} onClose={() => setProjectToDelete(null)} onDeleted={deleted => { setRevision(value => value + 1); setNotification({ message: `Project "${deleted.name}" has been deleted.`, kind: 'success' }); if (selectedId === deleted.id) { setSelectedId(''); navigate('projects'); } setProjectToDelete(null); }} />}
  </div>;
}


function ProjectsView({ projects, persistent, onSelect, onDelete, onCreate, onExplore }: { projects: readonly ProjectSummary[]; persistent: boolean; onSelect: (project: ProjectSummary) => void; onDelete: (project: ProjectSummary) => void; onCreate: () => void; onExplore: () => void }) {
  const [query, setQuery] = useState('');
  const [source, setSource] = useState('');
  const filtered = projects.filter(project => (!source || project.dataSource === source) && `${project.name} ${project.baseUrl} ${project.repositoryPath} ${project.languages.join(' ')}`.toLowerCase().includes(query.trim().toLowerCase()));
  function resetFilters() { setQuery(''); setSource(''); }
  return <>
    <div className="metric-grid">
      <Metric label="Total projects" value={projects.length.toString().padStart(2, '0')} detail={persistent ? 'In your local workspace' : 'In your current session'} icon="folder" />
      <Metric label="Discovery attached" value={projects.filter(project => project.dataSource !== 'project-input').length.toString().padStart(2, '0')} detail="Repository context available" icon="compass" />
      <Metric label="Code-aware ready" value={projects.filter(project => project.mode === 'code-aware').length.toString().padStart(2, '0')} detail="Projects with compatible adapters" icon="shield" />
      <Metric label="Scanned projects" value={projects.filter(project => project.scanState).length.toString().padStart(2, '0')} detail="Local static scan records" icon="activity" />
    </div>
    <Panel title="Applications" description="Open a project to review its discovery." extra={<span className="badge neutral">{projects.length} total</span>}>
      <div className="toolbar">
        <div className="search-field"><Icon name="search" /><label className="screen-reader-only" htmlFor="project-search">Search projects</label><input id="project-search" placeholder="Search name, target, or stack…" value={query} onChange={event => setQuery(event.target.value)} /></div>
        <label className="screen-reader-only" htmlFor="source-filter">Filter project source</label><select id="source-filter" className="filter-select" value={source} onChange={event => setSource(event.target.value)}><option value="">All sources</option><option value="saved-discovery">Saved discovery</option><option value="project-input">Setup only</option><option value="demo-fixture">Demo fixtures</option></select>
        {(query || source) && <button className="text-button" onClick={resetFilters}>Clear filters</button>}
        <span className="muted" role="status">{filtered.length} of {projects.length} projects</span>
      </div>
      {filtered.length === 0 ? <Empty title={projects.length ? 'No matching projects' : 'Add your first application'} action={<button className="button secondary" onClick={projects.length ? resetFilters : onCreate}>{projects.length ? 'Clear filters' : 'New project'}</button>}>{projects.length ? 'Try another name, target, stack, or data source.' : 'Connect your repository context and organize your security work.'}</Empty> : <div className="project-list">{filtered.map(project => <article className="project-card" key={project.id}>
        <div className="project-identity"><div className="project-icon"><Icon name="folder" /></div><div className="project-identity-text"><button className="row-link project-name" onClick={() => onSelect(project)}>{project.name}</button><p className="project-target mono">{project.baseUrl}</p></div></div>
        <div className="project-stack"><span className="card-label">STACK</span><div className="tag-list">{project.languages.length ? project.languages.map(language => <span className="tag" key={language}>{language}</span>) : <span className="muted">Discovery pending</span>}</div></div>
        <div className="project-mode"><span className="card-label">ANALYSIS MODE</span><ModeBadge mode={project.mode} /></div>
        <div className="project-source"><span className="card-label">DATA SOURCE</span><span className={`badge ${project.dataSource === 'demo-fixture' ? 'status-hypothesis' : 'neutral'}`}>{project.dataSource === 'demo-fixture' ? 'Demo fixture' : project.dataSource === 'saved-discovery' ? 'Saved discovery' : 'Setup only'}</span></div>
        <div className="project-actions">
          {project.id !== 'demo-shop' && project.dataSource !== 'demo-fixture' && (
            <button type="button" className="icon-button danger project-delete" aria-label={`Delete ${project.name}`} title={`Delete ${project.name}`} onClick={e => { e.stopPropagation(); onDelete(project); }}><Icon name="trash" /></button>
          )}
          <button type="button" className="project-open icon-button" aria-label={`Open ${project.name}`} onClick={() => onSelect(project)}><Icon name="arrow" /></button>
        </div>
      </article>)}</div>}
      <div className="panel-footnote"><Icon name="info" /><span>{persistent ? 'Projects, discovery, and the latest scan results are saved on this computer.' : 'Session only. Projects and imports reset when you reload.'}</span></div>
    </Panel>
    <div className="next-steps">
      <section className="next-step"><div className="step-icon"><Icon name="compass" /></div><div><div className="section-label">START WITH CONTEXT</div><h2>Bring your application into focus</h2><p>Add a repository and target, then run discovery or import a saved snapshot.</p><button className="text-button" onClick={onCreate}>Set up a project <Icon name="arrow" /></button></div></section>
      <section className="next-step"><div className="step-icon"><Icon name="shield" /></div><div><div className="section-label">EXPLORE THE WORKFLOW</div><h2>See what evidence looks like</h2><p>Review five example findings, their evidence, and suggested fixes.</p><button className="text-button" onClick={onExplore}>Explore demo findings <Icon name="arrow" /></button><span className="demo-caption">Synthetic evidence · no live tests</span></div></section>
    </div>
  </>;
}

function Technology({ label, values }: { label: string; values: readonly string[] }) {
  return <div className="technology-row"><span className="technology-label">{label}</span><div className="technology-value tag-list">{values.length ? values.map(value => <span key={value} className="tag">{value}</span>) : <span className="muted">Not detected</span>}</div></div>;
}
function DiscoveryView({ client, project, revision, onImport, onRescan, rescanning, onDelete }: { client: AgentOClient; project: ProjectSummary; revision: number; onImport: () => void; onRescan?: () => void; rescanning?: boolean; onDelete?: () => void }) {
  const canRefresh = onRescan && (client.storage === 'memory' || project.dataSource !== 'demo-fixture');
  const result = useRequest(() => client.getDiscovery(project.id), [client, project.id, revision]);
  if (result.loading) return <Loading />;
  if (result.error instanceof AgentOClientError && result.error.code === 'DISCOVERY_UNAVAILABLE') return <Panel title={project.name}><Empty title="Add your repository context" action={<div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>{canRefresh && <button className="button primary" onClick={onRescan} disabled={rescanning}><Icon name="compass" />{rescanning ? 'Scanning…' : 'Run discovery'}</button>}<button className="button secondary" onClick={onImport}><Icon name="file" />Import discovery JSON</button>{onDelete && project.id !== 'demo-shop' && project.dataSource !== 'demo-fixture' && <button type="button" className="button danger" onClick={onDelete}><Icon name="trash" />Delete project</button>}</div>}>This project has no saved discovery result. Run discovery or import the JSON created by AgentO's repository discovery CLI.</Empty></Panel>;
  if (result.error || !result.data) return <ErrorState retry={result.retry} />;
  const data = result.data;
  return <>
    {project.dataSource === 'demo-fixture' && <div className="fixture-banner"><Icon name="info" /><p><strong>Saved demo discovery.</strong> This seeded example is read-only. Create a project from a local demo shortcut to run real analysis. Scan results here remain fixtures.</p></div>}
    <div className="metric-grid"><Metric label="Languages" value={data.languages.length} detail={data.languages.join(' / ') || 'Not detected'} icon="file" /><Metric label="Dependencies" value={data.dependencies.length} detail="Direct manifest declarations" icon="folder" /><Metric label="Source files" value={data.structure.sourceFileCount} detail="From the saved repository inventory" icon="compass" /><Metric label="Analysis mode" value={<ModeBadge mode={data.mode} />} detail={data.expressAdapterAvailable ? 'Express adapter registered' : 'Express adapter unavailable'} icon="shield" /></div>
    {!data.supportedCodeAwareMode && <div className="notice warning"><Icon name="info" /><div><h3>Black-box mode selected</h3><ul>{data.fallbackReasons.map(reason => <li key={reason}>{reason}</li>)}</ul></div></div>}
    {data.diagnostics.length > 0 && <div className="notice error" role="status"><Icon name="info" /><div><h3>Discovery needs attention</h3><ul>{data.diagnostics.map((item, index) => <li key={index}><span className="mono">{item.file}</span>: {item.message}</li>)}</ul></div></div>}
    <div className="discovery-grid"><Panel title="Application fingerprint" description={project.name}><div className="surface-body"><Technology label="Languages" values={data.languages} /><Technology label="Frameworks" values={data.frameworks} /><Technology label="Database hints" values={data.databases} /><Technology label="ORM hints" values={data.orms} /><Technology label="Authentication" values={data.authentication} /><Technology label="Auth packages" values={data.authenticationPackages} /><Technology label="Available adapters" values={data.availableAdapterIds} /></div></Panel>
    <Panel title="Project & scope" description="Declared project metadata, not testing authorization."><div className="surface-body"><dl className="definition-grid"><div className="definition"><dt>Repository</dt><dd className="mono">{project.repositoryPath}</dd></div><div className="definition"><dt>Target URL</dt><dd className="mono">{project.baseUrl}</dd></div><div className="definition"><dt>Allowed origins</dt><dd>{project.allowedOrigins.map(origin => <div className="mono" key={origin}>{origin}</div>)}</dd></div><div className="definition"><dt>Snapshot name</dt><dd>{data.name}</dd></div></dl><div className="adapter-callout"><Icon name="shield" /><div><h3>{data.expressAdapterAvailable ? 'Adapter registered' : 'Express adapter unavailable'}</h3><p>Discovery describes source support. Backend policy checks will govern actual execution.</p></div></div>{((canRefresh) || (onDelete && project.id !== 'demo-shop' && project.dataSource !== 'demo-fixture')) && <div style={{ marginTop: 14, display: 'flex', gap: 10, flexWrap: 'wrap' }}>{canRefresh && <button type="button" className="button secondary" onClick={onRescan} disabled={rescanning}><Icon name="compass" />{rescanning ? 'Re-scanning repository…' : 'Re-scan this repository'}</button>}{onDelete && project.id !== 'demo-shop' && project.dataSource !== 'demo-fixture' && <button type="button" className="button danger" onClick={onDelete}><Icon name="trash" />Delete project</button>}</div>}</div></Panel></div>
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

function OutcomeBadge({ outcome }: { outcome: BrowserWorkflowResult['outcome'] }) {
  const cls = outcome === 'COMPLETED' ? 'status-confirmed' : outcome === 'FAILED' ? 'status-rejected' : 'status-not_reproduced';
  return <span className={`badge ${cls}`}>{outcome}</span>;
}

function StatusCodeBadge({ status, blocked }: { status: number | null; blocked?: boolean }) {
  if (blocked) return <span className="badge status-rejected mono">BLOCKED</span>;
  if (status === null) return <span className="badge neutral mono">PENDING</span>;
  const cls = status >= 200 && status < 300 ? 'status-confirmed'
    : status >= 300 && status < 400 ? 'mode-code-aware'
    : status >= 400 && status < 500 ? 'severity-high'
    : 'status-rejected';
  return <span className={`badge ${cls} mono`}>{status}</span>;
}

function WorkflowsView({ client, project, onDemo, onRunWorkflow }: { client: AgentOClient; project: ProjectSummary; onDemo: () => void; onRunWorkflow: () => void }) {
  const result = useRequest(() => client.getWorkflows(project.id), [client, project.id]);
  const [query, setQuery] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [identityFilter, setIdentityFilter] = useState('');
  const [selectedWorkflowId, setSelectedWorkflowId] = useState('');

  if (result.loading) return <Loading />;
  if (result.error || !result.data) return <ErrorState retry={result.retry} />;
  const all = result.data;

  if (!all.length) {
    return <Panel title="Browser Workflows">
      <Empty title="No browser workflows recorded" action={
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button type="button" className="button primary" onClick={onRunWorkflow}>
            <Icon name="plus" />
            Run a browser workflow
          </button>
          <button type="button" className="button secondary" onClick={onDemo}>
            Explore demo workflows
          </button>
        </div>
      }>
        Execute browser workflows to explore web applications, discover runtime API endpoints, verify authenticated personas, and record strict origin-scope network traffic.
      </Empty>
    </Panel>;
  }

  const identities = [...new Set(all.map(w => w.identityId))];
  const totalCompleted = all.filter(w => w.outcome === 'COMPLETED').length;
  const totalEndpoints = new Set(all.flatMap(w => w.endpoints.map(e => `${e.method} ${e.path}`))).size;
  const totalNetworkRecords = all.reduce((sum, w) => sum + w.network.length, 0);

  const filtered = all.filter(w => {
    const matchesOutcome = !outcomeFilter || w.outcome === outcomeFilter;
    const matchesIdentity = !identityFilter || w.identityId === identityFilter;
    const text = `${w.goal} ${w.identityId} ${w.personaLabel || ''} ${w.targetUrl} ${w.endpoints.map(e => e.path).join(' ')}`.toLowerCase();
    const matchesQuery = !query || text.includes(query.trim().toLowerCase());
    return matchesOutcome && matchesIdentity && matchesQuery;
  });

  const selected = filtered.find(w => w.id === selectedWorkflowId) ?? filtered[0];

  function resetFilters() {
    setQuery('');
    setOutcomeFilter('');
    setIdentityFilter('');
  }

  const fixtureOnly = all.every(w => w.sourceType === 'demo-fixture');
  const hasFixtures = all.some(w => w.sourceType === 'demo-fixture');

  return <>
    {hasFixtures && <div className="fixture-banner"><Icon name="info" /><p><strong>Browser workflow demonstrations.</strong> {fixtureOnly ? 'Recorded workflows verify multi-persona execution, session reuse, endpoint discovery, and scope enforcement.' : 'Contains recorded demonstrations alongside live results.'}</p></div>}

    <div className="metric-grid">
      <Metric label={fixtureOnly ? "Demo workflows" : "Recorded workflows"} value={all.length.toString().padStart(2, '0')} detail={fixtureOnly ? "Demonstrated browser runs" : "Total executed workflows"} icon="browser" />
      <Metric label="Completed outcomes" value={totalCompleted.toString().padStart(2, '0')} detail={`${Math.round(totalCompleted / (all.length || 1) * 100)}% successful goals`} icon="check" />
      <Metric label="Endpoints discovered" value={totalEndpoints.toString().padStart(2, '0')} detail="REST / SPA routes verified" icon="compass" />
      <Metric label="Network observations" value={totalNetworkRecords.toString().padStart(2, '0')} detail="Intercepted HTTP traffic" icon="activity" />
    </div>

    <div className="surface" style={{ marginBottom: 20 }}>
      <div className="toolbar">
        <div className="search-field">
          <Icon name="search" />
          <label className="screen-reader-only" htmlFor="workflow-search">Search workflows</label>
          <input id="workflow-search" placeholder="Search goal, persona, endpoint…" value={query} onChange={e => setQuery(e.target.value)} />
        </div>
        <label className="screen-reader-only" htmlFor="workflow-outcome-filter">Filter outcome</label>
        <select className="filter-select" id="workflow-outcome-filter" value={outcomeFilter} onChange={e => setOutcomeFilter(e.target.value)}>
          <option value="">All outcomes</option>
          <option value="COMPLETED">Completed</option>
          <option value="FAILED">Failed</option>
          <option value="SKIPPED">Skipped</option>
        </select>
        <label className="screen-reader-only" htmlFor="workflow-identity-filter">Filter persona</label>
        <select className="filter-select" id="workflow-identity-filter" value={identityFilter} onChange={e => setIdentityFilter(e.target.value)}>
          <option value="">All personas</option>
          {identities.map(id => <option key={id} value={id}>{id}</option>)}
        </select>
        {(query || outcomeFilter || identityFilter) && <button className="text-button" onClick={resetFilters}>Clear filters</button>}
        <span className="muted" role="status">{filtered.length} of {all.length} workflows</span>
      </div>
    </div>

    {selected ? (
      <div className="finding-layout">
        <Panel title="Workflow Queue" description="Select a browser workflow to inspect its full worked results.">
          <div className="finding-list">
            {filtered.map(wf => (
              <button
                key={wf.id}
                className={`finding-item ${selected.id === wf.id ? 'selected' : ''}`}
                onClick={() => setSelectedWorkflowId(wf.id)}
                aria-pressed={selected.id === wf.id}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span className="badge neutral mono">{wf.identityId}</span>
                  <OutcomeBadge outcome={wf.outcome} />
                </div>
                <h3 style={{ fontSize: 13, margin: '4px 0', textAlign: 'left' }}>{wf.goal}</h3>
                <div className="mono muted" style={{ fontSize: 11, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <span>{wf.endpoints.length} endpoint{wf.endpoints.length === 1 ? '' : 's'}</span>
                  <span>·</span>
                  <span>{wf.network.length} requests</span>
                  {wf.durationMs ? <><span>·</span><span>{(wf.durationMs / 1000).toFixed(2)}s</span></> : null}
                </div>
              </button>
            ))}
          </div>
        </Panel>

        <WorkflowDetailPanel key={selected.id} workflow={selected} onRerun={onRunWorkflow} />
      </div>
    ) : (
      <Panel title="Workflow Queue">
        <Empty title="No matching workflows" action={<button className="button secondary" onClick={resetFilters}>Clear filters</button>}>
          Try a different search term or select another persona filter.
        </Empty>
      </Panel>
    )}
  </>;
}

function WorkflowDetailPanel({ workflow, onRerun }: { workflow: BrowserWorkflowResult; onRerun: () => void }) {
  const fixture = workflow.sourceType === 'demo-fixture';
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'endpoints', label: `Endpoints (${workflow.endpoints.length})` },
    { id: 'network', label: `Network Traffic (${workflow.network.length})` },
    { id: 'steps', label: `Steps (${workflow.steps?.length ?? 0})` },
    { id: 'evidence', label: `Evidence (${workflow.evidence.length})` },
  ] as const;
  const [tab, setTab] = useState<(typeof tabs)[number]['id']>('overview');
  const [networkFilter, setNetworkFilter] = useState('');

  const filteredNetwork = workflow.network.filter(item => {
    if (!networkFilter) return true;
    if (networkFilter === 'blocked') return item.blocked;
    if (networkFilter === '2xx') return item.status && item.status >= 200 && item.status < 300;
    if (networkFilter === '3xx') return item.status && item.status >= 300 && item.status < 400;
    if (networkFilter === '4xx') return item.status && item.status >= 400 && item.status < 500;
    return true;
  });

  return (
    <section className="surface finding-detail" aria-label="Selected workflow">
      <div className="surface-heading">
        <div>
          <div className="eyebrow">{workflow.targetUrl} · PERSONA: {workflow.identityId.toUpperCase()}</div>
          <h2>{workflow.goal}</h2>
          <div className="tag-list" style={{ marginTop: 8 }}>
            <OutcomeBadge outcome={workflow.outcome} />
            <span className="badge neutral mono">{workflow.identityId}</span>
            {workflow.completionType && <span className="badge mode-code-aware">{workflow.completionType}</span>}
            {workflow.durationMs ? <span className="badge neutral">{(workflow.durationMs / 1000).toFixed(2)}s</span> : null}
            <span className="badge neutral">{workflow.actionsCount} actions</span>
          </div>
        </div>
        <button type="button" className="button secondary" onClick={onRerun}>
          <Icon name="activity" />
          Run Workflow
        </button>
      </div>

      {workflow.diagnostics.length > 0 && <div className="surface-body notice warning" role="status">
        <Icon name="info" /><div><strong>Workflow {workflow.outcome.toLowerCase()}</strong>
          <ul>{workflow.diagnostics.map((diagnostic, index) => <li key={index}><strong>{diagnostic.code}:</strong> {diagnostic.message}</li>)}</ul>
        </div>
      </div>}

      <div className="detail-tabs" role="tablist" aria-label="Workflow information">
        {tabs.map((item, index) => (
          <button
            key={item.id}
            role="tab"
            id={`workflow-tab-${item.id}`}
            aria-selected={tab === item.id}
            aria-controls={`workflow-panel-${item.id}`}
            tabIndex={tab === item.id ? 0 : -1}
            onClick={() => setTab(item.id)}
            onKeyDown={event => {
              if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
              event.preventDefault();
              const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
              const nextTab = tabs[next];
              if (nextTab) { setTab(nextTab.id); document.getElementById(`workflow-tab-${nextTab.id}`)?.focus(); }
            }}
          >
            {item.label}
          </button>
        ))}
      </div>

      {tabs.map(item => (
        <div
          key={item.id}
          role="tabpanel"
          id={`workflow-panel-${item.id}`}
          aria-labelledby={`workflow-tab-${item.id}`}
          hidden={tab !== item.id}
          tabIndex={0}
          className="surface-body detail-panel"
        >
          {item.id === 'overview' && <>
            <div className="section-label">WORKFLOW EXECUTION SUMMARY{fixture ? ' · DEMO' : ''}</div>
            <p className="muted">Completion describes browser goal progress. These observations carry no vulnerability verdict.</p>
            <dl className="definition-grid endpoint-summary">
              <div className="definition"><dt>Goal</dt><dd>{workflow.goal}</dd></div>
              <div className="definition"><dt>Persona / Identity</dt><dd className="mono">{workflow.personaLabel || workflow.identityId}</dd></div>
              <div className="definition"><dt>Target URL</dt><dd className="mono">{workflow.targetUrl}</dd></div>
              <div className="definition"><dt>Final Destination</dt><dd className="mono">{workflow.finalUrl || 'Initial / blank'}</dd></div>
              <div className="definition"><dt>Completion Mechanism</dt><dd className="mono">{workflow.completionType || 'unconfirmed'}</dd></div>
              <div className="definition"><dt>Actions Executed</dt><dd className="mono">{workflow.actionsCount} action(s)</dd></div>
              <div className="definition"><dt>Model Usage</dt><dd>{workflow.modelCalls ?? 0} calls · {workflow.modelTokens ?? 0} tokens</dd></div>
              <div className="definition"><dt>Recovery Attempts</dt><dd>{workflow.recoveryAttempts ?? 0}</dd></div>
            </dl>

            {workflow.session && (
              <>
                <div className="section-label" style={{ marginTop: 20 }}>AUTHENTICATED SESSION & ISOLATION</div>
                <div style={{ padding: '12px 16px', background: '#101722', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14, width: '100%' }}>
                    <div>
                      <span className="card-label">SESSION STATUS</span>
                      <div style={{ marginTop: 4 }}>
                        <span className={`badge ${workflow.session.authenticated ? 'status-confirmed' : 'status-rejected'}`}>
                          {workflow.session.authenticated ? 'Authenticated' : 'Unauthenticated'}
                        </span>
                      </div>
                    </div>
                    <div>
                      <span className="card-label">SESSION REUSE</span>
                      <div style={{ marginTop: 4 }}>
                        <span className="badge neutral">
                          {workflow.session.reused ? 'Reused from Cache/Disk' : 'Fresh Session Verified'}
                        </span>
                      </div>
                    </div>
                    {workflow.session.sessionRef && <div>
                      <span className="card-label">SESSION REF</span>
                      <div className="mono" style={{ marginTop: 4, color: 'var(--ink)' }}>{workflow.session.sessionRef}</div>
                    </div>}
                  </div>
                </div>
              </>
            )}

            {workflow.pageModelSummary && (
              <>
                <div className="section-label" style={{ marginTop: 24 }}>PAGE MODEL INSPECTION (NORMALIZED DOM)</div>
                <div className="surface" style={{ padding: 16, background: '#101722', border: '1px solid var(--border-subtle)' }}>
                  <p style={{ margin: '0 0 10px', fontSize: 13, color: 'var(--ink)' }}>
                    <strong>Page Title:</strong> <span className="mono">{workflow.pageModelSummary.title}</span>
                  </p>
                  <p style={{ margin: '0 0 10px', fontSize: 12 }}>
                    <strong>Interactive Elements:</strong> {workflow.pageModelSummary.interactiveElementCount} discovered elements (buttons, links, inputs)
                  </p>
                  {workflow.pageModelSummary.headings.length > 0 && (
                    <div>
                      <span className="card-label">HEADINGS DETECTED</span>
                      <div className="tag-list" style={{ marginTop: 6 }}>
                        {workflow.pageModelSummary.headings.map(h => <span key={h} className="tag">{h}</span>)}
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}

          </>}

          {item.id === 'endpoints' && <>
            <div className="section-label">DISCOVERED APPLICATION ENDPOINTS{fixture ? ' · DEMO' : ''}</div>
            <p style={{ fontSize: 13, marginBottom: 16, color: 'var(--muted)' }}>
              These endpoints were reached or called during the browser session, establishing live attack surface context.
            </p>
            {workflow.endpoints.length === 0 ? (
              <Empty title="No endpoints discovered">
                No distinct API endpoints were invoked during this browser workflow.
              </Empty>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Method</th>
                      <th scope="col">Endpoint Path</th>
                      <th scope="col">Auth</th>
                      <th scope="col">Roles</th>
                      <th scope="col">Parameters</th>
                    </tr>
                  </thead>
                  <tbody>
                    {workflow.endpoints.map((ep, i) => (
                      <tr key={ep.id || i}>
                        <td>
                          <span className={`badge ${ep.method === 'GET' ? 'mode-code-aware' : ep.method === 'POST' ? 'severity-high' : 'neutral'} mono`}>
                            {ep.method}
                          </span>
                        </td>
                        <td className="mono" style={{ color: 'var(--ink)', fontWeight: 600 }}>{ep.path}</td>
                        <td><span className="tag">{ep.authentication}</span></td>
                        <td>{ep.roles?.join(', ') || <span className="muted">Any</span>}</td>
                        <td className="mono">{ep.parameters?.map(p => `${p.name} (${p.location})`).join(', ') || 'None'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>}

          {item.id === 'network' && <>
            <div className="section-label">OBSERVED NETWORK TRAFFIC ({workflow.network.length})</div>
            <div className="toolbar" style={{ marginBottom: 16 }}>
              <span className="muted" style={{ fontSize: 12 }}>Filter traffic:</span>
              <button type="button" className={`button small ${!networkFilter ? 'primary' : 'secondary'}`} onClick={() => setNetworkFilter('')}>All ({workflow.network.length})</button>
              <button type="button" className={`button small ${networkFilter === '2xx' ? 'primary' : 'secondary'}`} onClick={() => setNetworkFilter('2xx')}>2xx Success</button>
              <button type="button" className={`button small ${networkFilter === '3xx' ? 'primary' : 'secondary'}`} onClick={() => setNetworkFilter('3xx')}>3xx Redirects</button>
              <button type="button" className={`button small ${networkFilter === 'blocked' ? 'primary' : 'secondary'}`} onClick={() => setNetworkFilter('blocked')}>Blocked Scope</button>
            </div>

            {filteredNetwork.length === 0 ? (
              <Empty title="No traffic matches filter">No network records match this filter.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Status</th>
                      <th scope="col">Method</th>
                      <th scope="col">URL</th>
                      <th scope="col">Type</th>
                      <th scope="col">Scope Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredNetwork.map((net, i) => (
                      <tr key={i}>
                        <td><StatusCodeBadge status={net.status} blocked={net.blocked} /></td>
                        <td className="mono">{net.method}</td>
                        <td className="mono" style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          <span title={net.url}>{net.url}</span>
                        </td>
                        <td><span className="tag">{net.resourceType}</span></td>
                        <td>
                          {net.blocked ? (
                            <span className="badge status-rejected mono" title={net.blockedReason}>
                              Refused: {net.blockedReason || 'origin-scope'}
                            </span>
                          ) : (
                            <span className="badge status-confirmed">In-scope</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>}

          {item.id === 'steps' && <>
            <div className="section-label">RECENT WORKFLOW STEPS</div>
            {!fixture && <p className="muted">Up to ten recent steps are retained. The action total also includes authentication actions.</p>}
            {(!workflow.steps || workflow.steps.length === 0) ? (
              <Empty title="No step records">
                Step-level logging was not retained for this workflow. Check the summary facts in Overview.
              </Empty>
            ) : (
              <ol className="timeline">
                {workflow.steps.map((st, i) => (
                  <li key={i} className={`timeline-item ${st.outcome === 'completed' ? 'completed' : 'failed'}`}>
                    <span className="timeline-marker" aria-hidden="true">
                      {st.outcome === 'completed' ? <Icon name="check" /> : '!'}
                    </span>
                    <div className="timeline-content">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span className="badge mode-code-aware mono">{st.actionType}</span>
                        <span className={`badge ${st.outcome === 'completed' ? 'status-confirmed' : 'status-rejected'}`}>{st.outcome}</span>
                      </div>
                      <p style={{ margin: 0, fontSize: 13, color: 'var(--ink)' }}>{st.details || st.actionType}</p>
                      {st.selector && <p className="mono muted" style={{ fontSize: 11, marginTop: 4 }}>Selector: {st.selector}</p>}
                      {st.url && <p className="mono muted" style={{ fontSize: 11, marginTop: 4 }}>URL: {st.url}</p>}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </>}

          {item.id === 'evidence' && <>
            <div className="section-label">EVIDENCE TRAIL ({workflow.evidence.length})</div>
            {workflow.evidence.map((evidence, index) => (
              <article className="evidence-card" key={evidence.id || index}>
                <div className="evidence-header">
                  <h3>
                    <span className="evidence-number">{index + 1}</span>
                    {evidence.kind.replaceAll('-', ' ')}
                  </h3>
                  <span className="badge neutral">{fixture ? 'Fixture evidence' : 'Recorded evidence'}</span>
                </div>
                <p>{evidence.summary}</p>
                <details className="evidence-metadata">
                  <summary>Structured facts & provenance</summary>
                  <dl className="evidence-facts">
                    {Object.entries(evidence.facts).map(([key, value]) => (
                      <div key={key}>
                        <dt>{key.replace(/([a-z])([A-Z])/g, '$1 $2')}</dt>
                        <dd>{typeof value === 'string' ? value : JSON.stringify(value)}</dd>
                      </div>
                    ))}
                  </dl>
                  <p className="evidence-source mono">{evidence.id} · {evidence.producerId}</p>
                </details>
              </article>
            ))}
            {!workflow.evidence.length && <p className="muted">No evidence items recorded for this workflow.</p>}
          </>}
        </div>
      ))}
    </section>
  );
}


function ScanView({ client, project, onDemo, onNavigateWorkflows }: { client: AgentOClient; project: ProjectSummary; onDemo: () => void; onNavigateWorkflows?: (() => void) | undefined }) {
  const result = useRequest(() => client.getScan(project.id), [client, project.id], {
    interval: 1000, while: scan => scan.state === 'pending' || scan.state === 'running',
  });
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState('');
  const [playing, setPlaying] = useState(false);
  const [step, setStep] = useState(0);
  const stages = result.data?.stages ?? [];
  useEffect(() => {
    if (!playing) return;
    if (step >= stages.length) { setPlaying(false); return; }
    const timer = window.setTimeout(() => setStep(value => value + 1), 650);
    return () => window.clearTimeout(timer);
  }, [playing, step, stages.length]);
  async function startScan() {
    setStarting(true); setStartError('');
    try { await client.startScan(project.id); result.retry(); }
    catch (error) { setStartError(clientErrorMessage(error)); result.retry(); }
    finally { setStarting(false); }
  }
  const active = starting || result.data?.state === 'pending' || result.data?.state === 'running';
  const controls = client.storage === 'disk' && project.dataSource !== 'demo-fixture'
    ? <button className="button primary" onClick={() => void startScan()} disabled={active}><Icon name="activity" />{active ? 'Scan in progress…' : 'Run static scan'}</button> : undefined;
  if (result.loading) return <Loading />;
  if (result.error instanceof AgentOClientError && result.error.code === 'SCAN_UNAVAILABLE') return <Panel title="Scan progress">{startError && <div className="notice error" role="alert">{startError}</div>}<Empty title="No scan has run" action={controls ?? <button className="button secondary" onClick={onDemo}>Explore the demo fixture</button>}>Run local discovery and Semgrep to collect source candidates, evidence, and remediation guidance. Runtime verification is unavailable. Setup and discovery alone do not produce findings.</Empty></Panel>;
  if (result.error || !result.data) return <ErrorState retry={result.retry} />;
  const fixture = result.data.source === 'demo-fixture';
  const completeCount = fixture && playing ? stages.slice(0, step).filter(stage => stage.status === 'complete').length : stages.filter(stage => stage.status === 'complete').length;
  const stageCount = fixture ? stages.length : stages.filter(stage => stage.status !== 'unavailable').length;
  const progress = stageCount ? Math.round(completeCount / stageCount * 100) : 0;
  const stateLabels = { pending: 'Scan pending', running: 'Scan in progress', complete: 'Scan complete', failed: 'Scan failed' };
  return <>{fixture && <FixtureNotice />}{startError && <div className="notice error" role="alert">{startError}</div>}{controls && <div className="heading-actions" style={{ marginBottom: 20 }}>{controls}</div>}<div className="scan-layout">
    <Panel title="Investigation timeline" description={fixture ? 'A replayable demonstration of the evidence workflow.' : 'The latest progress reported by the execution service.'} extra={<span className="badge neutral">{fixture ? 'Fixture' : 'Execution result'}</span>}>
      <div className="surface-body">
        <div className="progress-summary"><h3>{fixture ? playing ? 'Playing preview' : 'Demo snapshot complete' : stateLabels[result.data.state]}</h3><span className="muted">{completeCount} / {stageCount} available stages</span></div>
        <div className="progress-track" role="progressbar" aria-label={fixture ? 'Fixture workflow progress' : 'Scan workflow progress'} aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}><div className="progress-fill" style={{ width: `${progress}%` }} /></div>
        <ol className="timeline">{stages.map((stage, index) => {
          const state = stage.status === 'unavailable' || stage.status === 'failed' ? stage.status : fixture && playing ? index < step ? 'completed' : index === step ? 'active' : 'pending' : stage.status === 'complete' ? 'completed' : stage.status === 'running' ? 'active' : 'pending';
          const label = state === 'unavailable' ? 'Unavailable' : state === 'failed' ? 'Stage failed' : state === 'active' ? fixture ? 'Previewing' : 'In progress' : state === 'completed' ? fixture ? 'Fixture stage complete' : 'Stage complete' : fixture ? 'Preview pending' : 'Pending';
          return <li key={stage.id} className={`timeline-item ${state}`}><span className="timeline-marker" aria-hidden="true">{state === 'completed' ? <Icon name="check" /> : ['unavailable', 'failed'].includes(state) ? '!' : index + 1}</span><div className="timeline-content"><h3>{stage.label}</h3><p>{stage.details}</p><span className="timeline-meta">{label}</span></div></li>;
        })}</ol>
        {fixture && <button className="button primary" onClick={() => { if (playing) setPlaying(false); else { setStep(0); setPlaying(true); } }}><Icon name="activity" />{playing ? 'Stop preview' : 'Replay preview'}</button>}
      </div>
    </Panel>
    <div className="stack">
      <Panel title={fixture ? 'What this preview shows' : 'Scan summary'}>
        <div className="surface-body">
          <p className="muted" role="status">{result.data.summary}</p>
          {result.data.completedAt && <p className="help-text">Recorded: {new Date(result.data.completedAt).toLocaleString()}</p>}
          {Boolean(result.data.diagnostics?.length) && <div className="notice warning"><ul>{result.data.diagnostics!.map((diagnostic, index) => <li key={index}><strong>{diagnostic.code}</strong>: {diagnostic.message}</li>)}</ul></div>}
          {fixture && <div className="notice info" style={{ marginTop: 20, marginBottom: 0 }}><Icon name="info" /><p>Replay changes only this screen. It sends no requests to the configured target.</p></div>}
        </div>
      </Panel>
      {onNavigateWorkflows && (
        <Panel title="Browser Workflow Layer">
          <div className="surface-body">
            <p className="muted" style={{ marginBottom: 14 }}>
              Observe real user workflows, session auth, and discovered attack surfaces with network-level origin enforcement.
            </p>
            <button type="button" className="button secondary" onClick={onNavigateWorkflows}>
              <Icon name="browser" />
              View browser workflows
            </button>
          </div>
        </Panel>
      )}
      <Panel title="Current project"><div className="surface-body"><h3>{project.name}</h3><p className="mono muted" style={{ margin: '8px 0 18px' }}>{project.baseUrl}</p><ModeBadge mode={project.mode} /></div></Panel>
    </div>
  </div></>;
}

function FindingsView({ client, project, onDemo, onNavigateWorkflows }: { client: AgentOClient; project: ProjectSummary; onDemo: () => void; onNavigateWorkflows?: (() => void) | undefined }) {
  const result = useRequest(async () => {
    const scan = await client.getScan(project.id).catch(error => {
      if (error instanceof AgentOClientError && error.code === 'SCAN_UNAVAILABLE') return undefined;
      throw error;
    });
    return { scan, findings: await client.getFindings(project.id) };
  }, [client, project.id], { interval: 1000, while: data => data.scan?.state === 'pending' || data.scan?.state === 'running' });
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [selectedFinding, setSelectedFinding] = useState('');
  const [focusRequest, setFocusRequest] = useState(0);
  function clearFilters() { setQuery(''); setStatus(''); }
  function selectFinding(id: string) {
    setSelectedFinding(id);
    setFocusRequest(value => value + 1);
  }
  if (result.loading) return <Loading />;
  if (result.error || !result.data) return <ErrorState retry={result.retry} />;
  const all = result.data.findings;
  if (!all.length) return <Panel title="Findings"><Empty title="No findings recorded" action={<a className="button secondary" href="#scan">Open scan progress</a>}>{result.data.scan?.summary ?? 'This project has no scan results. Open scan progress to run local static analysis. Importing discovery does not produce findings.'}</Empty><button className="text-button" onClick={onDemo}>Explore the demo fixture</button></Panel>;
  const filtered = all.filter(finding => (!status || finding.status === status) && `${finding.title} ${finding.cweId} ${finding.endpoint?.path ?? ''}`.toLowerCase().includes(query.toLowerCase()));
  const selected = filtered.find(finding => finding.id === selectedFinding) ?? filtered[0];
  const fixtureOnly = all.every(finding => finding.sourceType === 'demo-fixture');
  const hasFixtures = all.some(finding => finding.sourceType === 'demo-fixture');
  return <>{hasFixtures && <FixtureNotice mixed={!fixtureOnly} />}<div className="metric-grid"><Metric label={fixtureOnly ? 'Fixture findings' : 'Findings'} value={all.length.toString().padStart(2, '0')} detail={fixtureOnly ? 'Synthetic investigation results' : 'Investigation results'} icon="shield" /><Metric label={fixtureOnly ? 'Confirmed fixtures' : 'Confirmed findings'} value={all.filter(finding => finding.status === 'CONFIRMED').length.toString().padStart(2, '0')} detail={fixtureOnly ? 'Demonstrates an evidence-backed verdict' : 'Evidence-backed verdicts'} icon="check" /><Metric label="Need investigation" value={all.filter(finding => ['HYPOTHESIS', 'LIKELY'].includes(finding.status)).length.toString().padStart(2, '0')} detail="Hypotheses and likely candidates" icon="search" /><Metric label={fixtureOnly ? 'Closed fixtures' : 'Closed findings'} value={all.filter(finding => ['NOT_REPRODUCED', 'REJECTED'].includes(finding.status)).length.toString().padStart(2, '0')} detail="Not reproduced or rejected" icon="file" /></div>
    <div className="surface" style={{ marginBottom: 20 }}><div className="toolbar"><div className="search-field"><Icon name="search" /><label className="screen-reader-only" htmlFor="finding-search">Search findings</label><input id="finding-search" placeholder="Search findings, CWE, or route…" value={query} onChange={event => setQuery(event.target.value)} /></div><label className="screen-reader-only" htmlFor="status-filter">Filter finding status</label><select className="filter-select" id="status-filter" value={status} onChange={event => setStatus(event.target.value)}><option value="">All statuses</option>{Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>{(query || status) && <button className="text-button" onClick={clearFilters}>Clear filters</button>}<span className="muted" role="status">{filtered.length} of {all.length} findings</span></div></div>
    {selected ? <div className="finding-layout"><Panel title="Investigation queue" description="Select a signal to review its evidence."><div className="finding-list">{filtered.map(finding => <button key={finding.id} className={`finding-item ${selected.id === finding.id ? 'selected' : ''}`} onClick={() => selectFinding(finding.id)} aria-pressed={selected.id === finding.id}><span className={`badge severity-${finding.severity}`}>{finding.severity}</span><FindingBadge status={finding.status} /><h3>{finding.title}</h3><div className="mono">{finding.cweId} · {finding.endpoint?.method} {finding.endpoint?.path ?? 'Source candidate'}</div></button>)}</div></Panel><FindingDetails client={client} projectId={project.id} findingId={selected.id} focusRequest={focusRequest} onNavigateWorkflows={onNavigateWorkflows} /></div> : <Panel title="Investigation queue"><Empty title="No matching findings" action={<button className="button secondary" onClick={clearFilters}>Clear filters</button>}>Try a different search or select another finding status.</Empty></Panel>}
  </>;
}
function FindingDetails({ client, projectId, findingId, focusRequest, onNavigateWorkflows }: { client: AgentOClient; projectId: string; findingId: string; focusRequest: number; onNavigateWorkflows?: (() => void) | undefined }) {
  const result = useRequest(() => client.getFinding(projectId, findingId), [client, projectId, findingId]);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (result.data?.id === findingId && focusRequest > 0 && window.matchMedia('(max-width: 1000px)').matches) {
      ref.current?.scrollIntoView({ block: 'start' });
      ref.current?.focus({ preventScroll: true });
    }
  }, [result.data, findingId, focusRequest]);
  return <div className="finding-detail-anchor" ref={ref} tabIndex={-1}>
    {result.loading ? <Panel title="Finding details"><Loading /></Panel> : result.error || !result.data ? <Panel title="Finding details"><ErrorState retry={result.retry} /></Panel> : <FindingDetailPanel key={findingId} finding={result.data} onNavigateWorkflows={onNavigateWorkflows} />}
  </div>;
}
function FindingDetailPanel({ finding, onNavigateWorkflows }: { finding: FindingDetail; onNavigateWorkflows?: (() => void) | undefined }) {
  const fixture = finding.sourceType === 'demo-fixture';
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'evidence', label: `Evidence (${finding.evidence.length})` },
    { id: 'remediation', label: 'Remediation' },
  ] as const;
  const [tab, setTab] = useState<(typeof tabs)[number]['id']>('overview');
  return <section className="surface finding-detail" aria-label="Selected finding">
    <div className="surface-heading"><div><div className="eyebrow">{finding.cweId} · {finding.owaspCategory}</div><h2>{finding.title}</h2><div className="tag-list"><FindingBadge status={finding.status} /><span className={`badge severity-${finding.severity}`}>{finding.severity} severity</span><span className="badge neutral">{finding.confidence} confidence</span></div></div></div>
    <div className="detail-tabs" role="tablist" aria-label="Finding information">{tabs.map((item, index) => <button key={item.id} role="tab" id={`finding-tab-${item.id}`} aria-selected={tab === item.id} aria-controls={`finding-panel-${item.id}`} tabIndex={tab === item.id ? 0 : -1} onClick={() => setTab(item.id)} onKeyDown={event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      const nextTab = tabs[next];
      if (nextTab) { setTab(nextTab.id); document.getElementById(`finding-tab-${nextTab.id}`)?.focus(); }
    }}>{item.label}</button>)}</div>
    {tabs.map(item => <div key={item.id} role="tabpanel" id={`finding-panel-${item.id}`} aria-labelledby={`finding-tab-${item.id}`} hidden={tab !== item.id} tabIndex={0} className="surface-body detail-panel">
      {item.id === 'overview' && <>
        <div className="section-label">ROOT CAUSE{fixture ? ' · FIXTURE' : ''}</div><p className="finding-summary">{finding.rootCause}</p>
        <dl className="definition-grid endpoint-summary"><div className="definition"><dt>Affected endpoint</dt><dd className="mono">{finding.endpoint ? `${finding.endpoint.method} ${finding.endpoint.path}` : 'No endpoint recorded'}</dd></div><div className="definition"><dt>Source location</dt><dd className="mono">{finding.source ? `${finding.source.file}:${finding.source.startLine}` : 'No source recorded'}</dd></div></dl>
        <div className="evidence-preview"><Icon name="file" /><div><h3>{finding.evidence.length} evidence {finding.evidence.length === 1 ? 'item' : 'items'} attached</h3><p>{fixture ? 'Synthetic examples illustrate how a verdict connects to its evidence.' : 'Review the observations that support this finding.'}</p><button className="text-button" onClick={() => { setTab('evidence'); document.getElementById('finding-tab-evidence')?.focus(); }}>Review evidence <Icon name="arrow" /></button></div></div>
        {onNavigateWorkflows && (
          <div className="notice info" style={{ marginTop: 16 }}>
            <Icon name="browser" />
            <div>
              <h3>Dynamic Browser Evidence</h3>
              <p>Explore runtime page models, intercepted HTTP responses, and session persistence in the Browser Workflow Layer.</p>
              <button type="button" className="button secondary small" style={{ marginTop: 8 }} onClick={onNavigateWorkflows}>
                <Icon name="browser" /> Open Browser Workflows
              </button>
            </div>
          </div>
        )}
      </>}
      {item.id === 'evidence' && <>
        <div className="section-label">EVIDENCE TRAIL{fixture ? ' · SYNTHETIC' : ''}</div>
        {finding.evidence.map((evidence, index) => <article className="evidence-card" key={evidence.id}><div className="evidence-header"><h3><span className="evidence-number">{index + 1}</span>{evidence.kind.replaceAll('-', ' ')}</h3><span className="badge neutral">{fixture ? 'Fixture evidence' : 'Recorded evidence'}</span></div><p>{evidence.summary}</p>{evidence.source && <p className="evidence-source mono">{evidence.source.file}:{evidence.source.startLine}</p>}<details className="evidence-metadata"><summary>Structured facts & provenance</summary><dl className="evidence-facts">{Object.entries(evidence.facts).map(([key, value]) => <div key={key}><dt>{key.replace(/([a-z])([A-Z])/g, '$1 $2')}</dt><dd>{typeof value === 'string' ? value : JSON.stringify(value)}</dd></div>)}</dl><p className="evidence-source mono">{evidence.id} · {evidence.producerId}</p></details></article>)}
        {!finding.evidence.length && <p className="muted">No evidence recorded for this finding.</p>}
      </>}
      {item.id === 'remediation' && <div className="remediation"><div className="section-label">SUGGESTED FIX{fixture ? ' · FIXTURE' : ''}</div><p>{finding.remediation.explanation}</p>{finding.remediation.patch && <pre>{finding.remediation.patch}</pre>}{finding.remediation.regressionTest && <div className="regression-guidance"><h3>Verify the fix</h3><p>{finding.remediation.regressionTest}</p></div>}</div>}
    </div>)}
  </section>;
}

function Dialog({ title, description, onClose, children, busy = false }: { title: string; description: string; onClose: () => void; children: ReactNode; busy?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    dialog?.showModal();
    dialog?.querySelector<HTMLInputElement>('input:not([type="file"])')?.focus({ preventScroll: true });
    return () => { dialog?.close(); document.body.style.overflow = overflow; };
  }, []);
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
    sequence.current += 1;
    setReading(false); setData(undefined); setFileName('');
    const parsed = parseSavedDiscovery(discoveryData);
    if (!parsed.ok) { setError(parsed.error); return undefined; }
    setData(parsed.value); setFileName(label); setError(''); return parsed.value;
  }
  return { data, error, fileName, reading, setReading, setError, read, setDirect };
}
function FileField({ saved, onRead, required = false }: { saved: ReturnType<typeof useSavedFile>; onRead: (file: File | undefined) => void; required?: boolean }) {
  return <div className="form-field full-width"><label htmlFor="discovery-file">Saved discovery JSON</label><input id="discovery-file" className="file-input" type="file" accept="application/json,.json" aria-describedby="discovery-file-help discovery-file-error" aria-invalid={Boolean(saved.error)} onChange={event => onRead(event.target.files?.[0])} /><p id="discovery-file-help" className="help-text">{required ? 'Choose' : 'Optionally attach'} the discovery CLI's JSON output, up to 2 MiB.</p>{saved.reading && <p role="status" className="help-text">Checking discovery file…</p>}{saved.fileName && <p role="status" className="help-text">Attached: {saved.fileName} · {saved.data?.structure.sourceFileCount} source files</p>}<p id="discovery-file-error" className="field-error" role={saved.error ? 'alert' : undefined}>{saved.error}</p></div>;
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
  const [scopeOpen, setScopeOpen] = useState(false);
  const [originsEdited, setOriginsEdited] = useState(false);
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

  function change(field: keyof typeof fields, value: string) {
    setFields(previous => {
      let origins = previous.origins;
      if (field === 'baseUrl' && !originsEdited) {
        try { origins = new URL(value).origin; } catch { /* Keep the last valid origin while typing. */ }
      }
      return { ...previous, origins, [field]: value };
    });
    const errorField = field === 'origins' ? 'allowedOrigins' : field;
    if (field === 'origins') setOriginsEdited(true);
    setErrors(previous => { const next = { ...previous }; delete next[errorField]; return next; });
    setError('');
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    const input: ProjectInput = { name: fields.name, repositoryPath: fields.repositoryPath, baseUrl: fields.baseUrl, allowedOrigins: fields.origins.split('\n').map(origin => origin.trim()).filter(Boolean) };
    const nextErrors = validateProjectInput(input);
    setErrors(nextErrors); setError('');
    if (Object.keys(nextErrors).length > 0) {
      if (nextErrors.allowedOrigins) setScopeOpen(true);
      window.requestAnimationFrame(() => document.getElementById(`project-${Object.keys(nextErrors)[0]}`)?.focus());
      return;
    }
    if (saved.error || saved.reading || discovering) return;
    setSaving(true);
    try { onSaved(await client.createProject(input, saved.data)); }
    catch (failure) { setError(clientErrorMessage(failure)); }
    finally { setSaving(false); }
  }

  return <Dialog title="New project" description="Add your application. Attach repository context when you're ready." onClose={onClose} busy={saving || discovering}><form noValidate onSubmit={submit}><div className="dialog-body">
    {demoApps.length > 0 && <div className="demo-quickstart"><div className="quickstart-heading"><Icon name="compass" /><div><h3>Try a local demo</h3><p>Fill in the project and discover its repository.</p></div></div><div className="tag-list">{demoApps.map(demo => <button key={demo.id} type="button" className="button secondary small" disabled={saving || discovering || saved.reading} onClick={() => {
      const isDemo2 = demo.name === 'demo-app-02';
      setOriginsEdited(false); setErrors({});
      setFields({ name: demo.name, repositoryPath: demo.path, baseUrl: isDemo2 ? 'http://localhost:4000' : 'http://localhost:3000', origins: isDemo2 ? 'http://localhost:4000' : 'http://localhost:3000' });
      void runLocalDiscovery(demo.path);
    }}>{demo.name}<Icon name="arrow" /></button>)}</div></div>}
    <fieldset className="form-section" disabled={saving || discovering}>
      <legend>Application details</legend>
      <div className="form-grid">
        <div className="form-field full-width"><label htmlFor="project-name">Project name</label><input id="project-name" placeholder="e.g. Storefront API" value={fields.name} onChange={event => change('name', event.target.value)} aria-invalid={Boolean(errors.name)} aria-describedby="name-error" autoFocus maxLength={120} /><p id="name-error" className="field-error">{errors.name}</p></div>
        <div className="form-field full-width"><label htmlFor="project-repositoryPath">Repository path</label><div className="repository-input"><input id="project-repositoryPath" placeholder="/path/to/your/repository" value={fields.repositoryPath} onChange={event => change('repositoryPath', event.target.value)} aria-invalid={Boolean(errors.repositoryPath)} aria-describedby="repository-help repository-error" /><button type="button" className="button secondary" onClick={() => void runLocalDiscovery()} disabled={discovering || saved.reading || !fields.repositoryPath.trim()}><Icon name="compass" />{discovering ? 'Discovering…' : 'Discover'}</button></div><p id="repository-help" className="help-text">A local path on this computer. Discovery is optional during setup.</p><p id="repository-error" className="field-error">{errors.repositoryPath}</p></div>
        <div className="form-field full-width"><label htmlFor="project-baseUrl">Target URL</label><input id="project-baseUrl" type="url" value={fields.baseUrl} onChange={event => change('baseUrl', event.target.value)} aria-invalid={Boolean(errors.baseUrl)} aria-describedby="target-help target-error" /><p id="target-help" className="help-text">The running application you intend to test.</p><p id="target-error" className="field-error">{errors.baseUrl}</p></div>
      </div>
    </fieldset>
    <details className="form-options" open={scopeOpen} onToggle={event => setScopeOpen(event.currentTarget.open)}><summary><span>Allowed origins</span><span className="option-hint">Customize scope</span></summary><fieldset className="form-section" disabled={saving || discovering}><div className="form-field"><label htmlFor="project-allowedOrigins">Allowed origins</label><textarea id="project-allowedOrigins" value={fields.origins} onChange={event => change('origins', event.target.value)} aria-invalid={Boolean(errors.allowedOrigins)} aria-describedby="origins-help origins-error" rows={2} /><p id="origins-help" className="help-text">One explicit origin per line. Your target's origin is included automatically until you customize this list.</p><p id="origins-error" className="field-error">{errors.allowedOrigins}</p></div></fieldset></details>
    <details className="form-options"><summary><span>Attach saved discovery</span><span className="option-hint">Optional</span></summary><fieldset className="form-section" disabled={saving || discovering}><FileField saved={saved} onRead={file => { void saved.read(file).then(discovery => { if (discovery) setFields(previous => ({ ...previous, name: previous.name || discovery.name, repositoryPath: previous.repositoryPath || discovery.repositoryPath })); }); }} /></fieldset></details>
    {saved.data && <div className="notice success attachment-status" role="status"><Icon name="check" /><p><strong>Discovery attached</strong><br />{saved.data.structure.sourceFileCount} source files · {saved.data.mode} analysis</p></div>}
    {error && <div className="notice error form-error" role="alert">{error}</div>}
    <p className="help-text form-boundary"><Icon name="info" />{client.storage === 'disk' ? 'Saved on this computer.' : 'Session only.'} Creating a project does not start a security scan.</p>
  </div><div className="dialog-footer"><button type="button" className="button secondary" onClick={onClose} disabled={saving || discovering}>Cancel</button><button className="button primary" disabled={saving || discovering || saved.reading || Boolean(saved.error)}>{saving ? 'Creating…' : 'Create project'}<Icon name="arrow" /></button></div></form></Dialog>;
}

function DeleteProjectDialog({ client, project, onClose, onDeleted }: { client: AgentOClient; project: ProjectSummary; onClose: () => void; onDeleted: (project: ProjectSummary) => void }) {
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState('');

  async function handleDelete(event: React.FormEvent) {
    event.preventDefault();
    setDeleting(true);
    setError('');
    try {
      await client.deleteProject(project.id);
      onDeleted(project);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete project.');
      setDeleting(false);
    }
  }

  return <Dialog title="Delete project" description={`Permanently remove "${project.name}" from your workspace?`} onClose={onClose} busy={deleting}>
    <form onSubmit={handleDelete}>
      <div className="dialog-body">
        <div className="notice warning" role="alert">
          <Icon name="info" />
          <div>
            <h3>Irreversible Action</h3>
            <p>Deleting <strong>{project.name}</strong> will permanently remove its configuration, saved discovery snapshots, local static scan records, and workflow observations from your workspace.</p>
          </div>
        </div>
        <dl className="definition-grid" style={{ marginTop: 16 }}>
          <div className="definition"><dt>Project Name</dt><dd><strong>{project.name}</strong></dd></div>
          <div className="definition"><dt>Target URL</dt><dd className="mono">{project.baseUrl}</dd></div>
          {project.repositoryPath && <div className="definition"><dt>Repository</dt><dd className="mono">{project.repositoryPath}</dd></div>}
        </dl>
        {error && <div className="notice error form-error" role="alert">{error}</div>}
      </div>
      <div className="dialog-footer">
        <button type="button" className="button secondary" onClick={onClose} disabled={deleting}>Cancel</button>
        <button type="submit" className="button danger" disabled={deleting}><Icon name="trash" />{deleting ? 'Deleting…' : 'Delete project'}</button>
      </div>
    </form>
  </Dialog>;
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
      {discovering ? 'Scanning repository…' : 'Discover this repository'}
    </button>
  </div>
  <FileField required saved={saved} onRead={file => { setError(''); void saved.read(file); }} />{error && <div className="notice error" role="alert">{error}</div>}<p className="help-text">This replaces the saved discovery snapshot. It does not create scan results or evidence.</p></div><div className="dialog-footer"><button type="button" className="button secondary" onClick={onClose} disabled={saving || discovering}>Cancel</button><button className="button primary" disabled={saving || discovering || saved.reading || !saved.data || Boolean(saved.error)}>{saving ? 'Importing…' : 'Import snapshot'}</button></div></form></Dialog>;
}

function WorkflowRunDialog({
  client,
  project,
  onClose,
  onCompleted,
}: {
  client: AgentOClient;
  project: ProjectSummary;
  onClose: () => void;
  onCompleted: (workflow: BrowserWorkflowResult) => void;
}) {
  const [goal, setGoal] = useState(workflowProfiles[0]!.suggestedGoal);
  const [identityId, setIdentityId] = useState('alice');
  const [targetName, setTargetName] = useState('storefront');
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');

  const [planningMode, setPlanningMode] = useState<'automatic' | 'recipes'>('automatic');
  const profile = workflowProfiles.find(item => item.id === targetName)!;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!goal.trim()) {
      setError('Please provide a workflow goal.');
      return;
    }
    setRunning(true);
    setError('');
    try {
      const result = await client.runWorkflow(project.id, {
        goal: goal.trim(),
        identityId,
        targetName,
        planningMode,
      });
      onCompleted(result);
      onClose();
    } catch (err: unknown) {
      setError(clientErrorMessage(err));
    } finally {
      setRunning(false);
    }
  }

  return (
    <Dialog
      title="Run browser workflow"
      description={`Execute an automated browser session against ${project.name} (${project.baseUrl}).`}
      onClose={onClose}
      busy={running}
    >
      <form noValidate onSubmit={submit}>
        <div className="dialog-body">
          <div className="demo-quickstart" style={{ marginBottom: 16 }}>
            <div className="quickstart-heading">
              <Icon name="browser" />
              <div>
                <h3>Describe your goal</h3>
                <p>Automatic planning uses a model for unfamiliar goals. Listed recipes run without model calls.</p>
              </div>
            </div>
            <div className="tag-list" style={{ marginTop: 10 }}>
              <button type="button" className="button secondary small" disabled={running}
                onClick={() => { setGoal(profile.suggestedGoal); setPlanningMode('automatic'); }}>Try a natural-language goal</button>
              {profile.recipeGoals.map(recipe => <button key={recipe} type="button" className="button secondary small" disabled={running}
                onClick={() => { setGoal(recipe); setError(''); }}>{recipe}</button>)}
            </div>
          </div>

          <fieldset className="form-section" disabled={running}>
            <legend>Workflow parameters</legend>
            <div className="form-grid">
              <div className="form-field full-width">
                <label htmlFor="workflow-goal">Goal description</label>
                <textarea
                  id="workflow-goal"
                  rows={3}
                  maxLength={2000}
                  value={goal}
                  onChange={e => { setGoal(e.target.value); setError(''); }}
                  placeholder="e.g. Navigate to checkout and inspect network traffic"
                  required
                />
              </div>
              <div className="form-field">
                <label htmlFor="workflow-identity">Persona / Identity</label>
                <select
                  id="workflow-identity"
                  className="filter-select"
                  value={identityId}
                  onChange={e => setIdentityId(e.target.value)}
                >
                  {profile.personas.map(persona => <option key={persona.id} value={persona.id}>{persona.label}</option>)}
                </select>
              </div>
              <div className="form-field">
                <label htmlFor="workflow-target">Adapter Profile</label>
                <select
                  id="workflow-target"
                  className="filter-select"
                  value={targetName}
                  onChange={e => {
                    const next = workflowProfiles.find(item => item.id === e.target.value)!;
                    setTargetName(next.id); setIdentityId(next.personas[0]!.id); setGoal(next.suggestedGoal); setError('');
                  }}
                >
                  {workflowProfiles.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
                </select>
              </div>
              <div className="form-field full-width">
                <label htmlFor="workflow-planning">Planning</label>
                <select id="workflow-planning" value={planningMode} onChange={e => setPlanningMode(e.target.value as 'automatic' | 'recipes')}>
                  <option value="automatic">Automatic — recipes first, then model planning</option>
                  <option value="recipes">Recipes only — no model calls</option>
                </select>
                <p className="muted">Uses the selected persona and allowed origins. Built-in profiles are for local demo applications.</p>
              </div>
            </div>
          </fieldset>

          {error && <div className="notice error form-error" role="alert">{error}</div>}

          <div className="notice info" style={{ marginTop: 12 }}>
            <Icon name="info" />
            <p>
              {client.storage === 'disk'
                ? 'Records browser actions and network evidence. Natural-language planning requires a model configured on the local service. Completion records goal progress; security findings require separate verification.'
                : 'Demo mode simulates execution and appends the observed workflow record to your session.'}
            </p>
          </div>
        </div>

        <div className="dialog-footer">
          <button type="button" className="button secondary" onClick={onClose} disabled={running}>
            Cancel
          </button>
          <button className="button primary" disabled={running || !goal.trim()}>
            <Icon name="browser" />
            {running ? 'Executing workflow…' : 'Run workflow'}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

