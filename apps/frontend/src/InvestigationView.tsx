import { useEffect, useRef, useState } from 'react';
import type { AgentOClient, InvestigationHypothesis, InvestigationPlan, InvestigationSnapshot, ProjectSummary } from './client/types';

const readable = (value: string) => value.replaceAll('-', ' ').replaceAll('.', ' ');
const date = (value: string | null) => value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Not generated yet';
const requirements: Record<string, string> = {
  'authorization-policy-required': 'Declare who owns the resource and who must be denied access.',
  'unauthorized-control-required': 'Declare an identity or anonymous request that must be denied.',
  'distinct-authenticated-identities-required': 'Provide two distinct authenticated identities.',
  'eligible-identity-required': 'Provide an identity with the required role.',
  'authentication-unknown': 'Establish whether this endpoint needs authentication.',
  'owned-resource-required': 'Establish an owner-bound resource from evidence.',
  'conflicting-ownership': 'Resolve the conflicting resource ownership observations.',
  'input-required': 'Bind a private baseline input on the execution host.',
  'body-encoding-required': 'Declare whether the request body uses JSON or form encoding.',
  'sensitive-cookie-names-required': 'Declare which cookies contain sensitive session data.',
  'untrusted-origins-required': 'Declare the untrusted origins to check.',
  'https-required': 'Provide an HTTPS target for the Secure cookie check.',
};
const actions: Record<string, string> = {
  'session.establish': 'Establish an isolated session', 'resource.identify': 'Identify the owned resource',
  'request.baseline': 'Collect the baseline response', 'request.as-attacker': 'Request as the other identity',
  'request.anonymous': 'Request without authentication', 'cookies.collect': 'Inspect cookie attributes',
  'cors.preflight': 'Check the preflight response', 'cors.actual': 'Check the cross-origin response',
  'xss.inject-canary': 'Send the controlled canary', 'xss.collect-execution': 'Collect execution observations',
  'sql.syntax': 'Check a syntax control', 'sql.boolean-true': 'Check the true condition',
  'sql.boolean-false': 'Check the false condition', 'responses.compare': 'Compare the responses', verify: 'Evaluate the collected evidence',
};
const diagnostics: Record<string, string> = {
  'model-changed': 'New observations are available. Regenerate to bring these hypotheses and plans up to date.',
  'planning-packages-unavailable': 'Planning packages are unavailable. Build the CWE rules, hypothesis engine, and test planner, then retry.',
  'no-plans': 'Some hypotheses have no test draft because the rule has insufficient planning context.',
  'unsupported-method': 'Some request methods are outside the available probe support.',
  'plan-limit': 'The plan limit was reached. This result shows partial coverage.',
};

export function InvestigationView({ client, project, view, focusHypothesis, onOpenPlans }: {
  client: AgentOClient; project: ProjectSummary; view: 'hypotheses' | 'plans';
  focusHypothesis: string; onOpenPlans: (hypothesisId: string) => void;
}) {
  const [snapshot, setSnapshot] = useState<InvestigationSnapshot>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [query, setQuery] = useState('');
  const [readiness, setReadiness] = useState('');
  const [cwe, setCwe] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const mounted = useRef(false);
  const inspectorHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  useEffect(() => {
    let active = true;
    setLoading(true); setError('');
    void client.getInvestigation(project.id).then(result => {
      if (active) { setSnapshot(result); setLoading(false); }
    }).catch(() => { if (active) { setError('Investigation data could not be loaded. Check the local service and retry.'); setLoading(false); } });
    return () => { active = false; };
  }, [client, project.id, revision]);
  useEffect(() => { setSelectedId(''); setQuery(''); setReadiness(''); setCwe(''); }, [view, focusHypothesis]);

  async function generate() {
    setBusy(true); setError('');
    try {
      const result = await client.refreshInvestigation(project.id);
      if (mounted.current) setSnapshot(result);
    } catch (error) {
      if (mounted.current) setError(error instanceof Error ? error.message : 'Planning failed. Check the local service and retry.');
    } finally { if (mounted.current) setBusy(false); }
  }
  function select(id: string) {
    setSelectedId(id);
    requestAnimationFrame(() => { inspectorHeading.current?.focus(); inspectorHeading.current?.scrollIntoView({ block: 'nearest', behavior: 'instant' }); });
  }
  if (loading) return <div className="loading-state" role="status"><span className="spinner" aria-hidden="true" />Loading investigation…</div>;
  if (!snapshot) return <section className="surface"><div className="error-state" role="alert"><h2>Investigation unavailable</h2><p>{error}</p><button className="button secondary" onClick={() => setRevision(value => value + 1)}>Try again</button></div></section>;
  const fixture = snapshot.sourceType === 'demo-fixture';
  const ready = snapshot.plans.filter(plan => plan.readiness === 'READY').length;
  const order = (a: { cweId: string }, b: { cweId: string }) => Number(a.cweId.slice(4)) - Number(b.cweId.slice(4));
  const hypotheses = snapshot.hypotheses.filter(item => (!cwe || item.cweId === cwe) && `${item.title} ${item.cweId} ${item.endpoint?.path ?? ''} ${item.reason}`.toLowerCase().includes(query.trim().toLowerCase())).sort((a, b) => order(a, b) || (a.endpoint?.path ?? '').localeCompare(b.endpoint?.path ?? ''));
  const plans = snapshot.plans.filter(item => (!cwe || item.cweId === cwe) && `${item.title} ${item.cweId} ${item.probeId} ${item.testedInput?.name ?? ''}`.toLowerCase().includes(query.trim().toLowerCase()) && (!readiness || item.readiness === readiness)).sort(order);
  const selectedHypothesis = hypotheses.find(item => item.id === selectedId) ?? hypotheses[0];
  const selectedPlan = plans.find(item => item.id === selectedId) ?? plans.find(item => item.hypothesisId === focusHypothesis) ?? plans[0];
  const entries = view === 'hypotheses' ? hypotheses : plans;
  const clear = () => { setQuery(''); setReadiness(''); setCwe(''); };

  return <div className="investigation-view">
    {fixture && <div className="fixture-banner"><p><strong>Synthetic example.</strong> These hypotheses and plans come from the demo model. No live security tests were run.</p></div>}
    <div className="investigation-command">
      <div><span className={`badge ${snapshot.state === 'stale' || snapshot.state === 'partial' ? 'status-likely' : 'neutral'}`}>{!snapshot.generatedAt && snapshot.state !== 'unavailable' ? 'Not generated' : snapshot.state === 'ready' ? 'Saved analysis' : `${snapshot.state[0]!.toUpperCase()}${snapshot.state.slice(1)} analysis`}</span><p>{snapshot.generatedAt ? `Generated ${date(snapshot.generatedAt)}` : 'Generate from your saved application model.'}</p></div>
      {!fixture && snapshot.generatedAt && <button className="button primary" disabled={busy || snapshot.sourceState === 'empty'} onClick={() => void generate()}>{busy ? 'Generating…' : 'Regenerate analysis'}</button>}
    </div>
    <ol className="proof-trail" aria-label="Investigation stages">
      <li><a href="#model"><span className="trail-dot observed" aria-hidden="true" /><strong>Observations</strong><span>{snapshot.sourceState === 'empty' ? 'Collect context first' : `${snapshot.sourceState} application model`}</span></a></li>
      <li className={view === 'hypotheses' ? 'current' : ''}><a href="#hypotheses"><span className="trail-dot reasoned" aria-hidden="true" /><strong>Hypotheses</strong><span>{snapshot.hypotheses.length} evidence-linked questions</span></a></li>
      <li className={view === 'plans' ? 'current' : ''}><a href="#plans"><span className="trail-dot planned" aria-hidden="true" /><strong>Test plans</strong><span>{ready} ready · {snapshot.plans.length - ready} blocked</span></a></li>
      <li><span className="trail-final"><span className="trail-dot inactive" aria-hidden="true" /><strong>Verification</strong><span>Execution not configured</span></span></li>
    </ol>
    {error && <div className="notice error" role="alert"><p>{error}</p><button className="button small secondary" onClick={() => void generate()} disabled={busy}>Retry</button></div>}
    {snapshot.state === 'stale' && <div className="notice warning" role="status"><p>This analysis uses older observations. Regenerate to include the latest application model.</p></div>}
    {snapshot.sourceState === 'partial' && <div className="notice info"><p>Coverage is partial. These results use the saved observations available.</p></div>}
    {snapshot.diagnostics.length > 0 && <details className="investigation-diagnostics"><summary>Analysis notes ({snapshot.diagnostics.length})</summary><ul>{snapshot.diagnostics.map(code => <li key={code}>{diagnostics[code] ?? `Analysis reported ${readable(code)}. Review coverage before drawing conclusions.`}</li>)}</ul></details>}
    {!snapshot.generatedAt || snapshot.sourceState === 'empty' ? <section className="surface"><div className="empty-state"><div className="empty-symbol" aria-hidden="true">?</div><h2>{snapshot.sourceState === 'empty' ? 'Start with application context' : 'Your observations are ready to investigate'}</h2><p>{snapshot.sourceState === 'empty' ? 'Run a static scan or a browser workflow to collect observations. Then generate evidence-linked questions and proposed checks here.' : 'Generate hypotheses and test plans from the saved model. Planning uses local observations and sends no requests to your target.'}</p><div className="model-actions">{snapshot.sourceState === 'empty' ? <><a className="button primary" href="#scan">Run a static scan</a><a className="button secondary" href="#workflows">Observe a workflow</a></> : <button className="button primary" onClick={() => void generate()} disabled={busy}>{busy ? 'Generating…' : 'Generate hypotheses & plans'}</button>}<a className="text-button" href="#model">Inspect application model</a></div></div></section> : <section className="surface investigation-workbench">
      <div className="surface-heading"><div><h2>{view === 'hypotheses' ? 'Investigation queue' : 'Proposed security checks'}</h2><p className="surface-description">{view === 'hypotheses' ? 'Review the question, follow its evidence, then inspect the plan.' : 'Inspect readiness, required capabilities, and evidence to collect.'}</p></div><span className="badge neutral">{entries.length} {view === 'hypotheses' ? 'hypotheses' : 'plans'}</span></div>
      <div className="toolbar"><label className="investigation-search"><span className="screen-reader-only">Search {view === 'hypotheses' ? 'hypotheses' : 'test plans'}</span><input type="search" placeholder={view === 'hypotheses' ? 'Search questions, routes, or CWE…' : 'Search plans, probes, or CWE…'} value={query} onChange={event => setQuery(event.target.value)} /></label><label className="investigation-filter"><span className="screen-reader-only">Weakness type</span><select value={cwe} onChange={event => setCwe(event.target.value)}><option value="">All weaknesses</option>{[...snapshot.coverage].sort(order).map(item => <option key={item.cweId} value={item.cweId}>{item.cweId} · {item.title}</option>)}</select></label>{view === 'plans' && <label className="investigation-filter"><span className="screen-reader-only">Plan readiness</span><select value={readiness} onChange={event => setReadiness(event.target.value)}><option value="">All readiness states</option><option value="READY">Ready</option><option value="BLOCKED">Blocked</option></select></label>}{(query || readiness || cwe) && <button className="text-button" onClick={clear}>Clear filters</button>}</div>
      {entries.length ? <div className="investigation-split"><div className="investigation-queue" aria-label={view === 'hypotheses' ? 'Hypotheses' : 'Test plans'}>{view === 'hypotheses' ? hypotheses.map(item => <button className={`investigation-item ${item.id === selectedHypothesis?.id ? 'selected' : ''}`} key={item.id} onClick={() => select(item.id)} aria-pressed={item.id === selectedHypothesis?.id}><span className="queue-meta"><span>{item.cweId}</span><span>{item.origin === 'deterministic' ? 'Rule grounded' : 'Model assisted'}</span></span><strong>{item.title}</strong><span className="queue-route mono">{item.endpoint ? `${item.endpoint.method} ${item.endpoint.path}` : 'Endpoint context unavailable'}</span><span className="queue-input">{snapshot.plans.filter(plan => plan.hypothesisId === item.id && plan.testedInput).map(plan => `${plan.testedInput!.location}: ${plan.testedInput!.name}`).join(', ')}</span><span className="queue-foot">{item.evidence.length} evidence records · {snapshot.plans.filter(plan => plan.hypothesisId === item.id).length} proposed checks</span></button>) : plans.map(item => <button className={`investigation-item ${item.id === selectedPlan?.id ? 'selected' : ''}`} key={item.id} onClick={() => select(item.id)} aria-pressed={item.id === selectedPlan?.id}><span className="queue-meta"><span>{item.cweId}</span><span className={`readiness ${item.readiness.toLowerCase()}`}>{item.readiness === 'READY' ? 'Ready' : 'Blocked'}</span></span><strong>{item.title}</strong><span className="queue-route">{readable(item.probeId)} · {item.steps.length} steps</span><span className="queue-input">{item.testedInput ? `${item.testedInput.location}: ${item.testedInput.name}` : ''}</span><span className="queue-foot">{item.prerequisites.length ? `${item.prerequisites.length} prerequisites to resolve` : 'Planning prerequisites present'}</span></button>)}</div>
        <div className="investigation-inspector">{view === 'hypotheses' && selectedHypothesis ? <HypothesisDetail hypothesis={selectedHypothesis} plans={snapshot.plans.filter(plan => plan.hypothesisId === selectedHypothesis.id)} headingRef={inspectorHeading} onOpenPlans={onOpenPlans} /> : selectedPlan && <PlanDetail plan={selectedPlan} hypothesis={snapshot.hypotheses.find(item => item.id === selectedPlan.hypothesisId)} headingRef={inspectorHeading} />}</div>
      </div> : <div className="empty-state"><h2>{query || readiness || cwe ? 'No matching results' : view === 'hypotheses' ? 'No grounded hypotheses yet' : 'No test drafts available'}</h2><p>{query || readiness || cwe ? 'Try a different search or clear the filters.' : 'The saved observations do not provide enough context for this result. Review the application model and analysis notes. An empty result does not establish safety.'}</p>{(query || readiness || cwe) ? <button className="button secondary" onClick={clear}>Clear filters</button> : <a className="button secondary" href="#model">Review application model</a>}</div>}
    </section>}
    <Coverage snapshot={snapshot} />
    <p className="investigation-footnote">Hypotheses describe questions to investigate. Ready describes planning prerequisites. Runtime execution and vulnerability verdicts require separate verification.</p>
  </div>;
}

type HeadingRef = React.RefObject<HTMLHeadingElement | null>;
function HypothesisDetail({ hypothesis, plans, headingRef, onOpenPlans }: { hypothesis: InvestigationHypothesis; plans: readonly InvestigationPlan[]; headingRef: HeadingRef; onOpenPlans: (id: string) => void }) {
  return <article><div className="inspector-meta"><span className="badge status-hypothesis">Hypothesis</span><span className="muted">{hypothesis.cweId}</span></div><h2 ref={headingRef} tabIndex={-1}>{hypothesis.title}</h2>{hypothesis.endpoint && <p className="inspector-route mono"><span>{hypothesis.endpoint.method}</span> {hypothesis.endpoint.path}</p>}
    <section className="inspector-section"><h3>Why investigate this?</h3><p>{hypothesis.reason}</p></section>
    <details className="inspector-section support-details"><summary>Supporting observations ({hypothesis.supports.length})</summary>{hypothesis.supports.map((support, index) => <div className="support-observation" key={index}><p>{support.statement}</p><span>{support.evidenceIds.length} linked evidence records</span></div>)}</details>
    <section className="inspector-section"><div className="section-heading"><h3>Proposed checks</h3><span className="muted">{plans.length}</span></div>{plans.length ? <><p>{plans.filter(plan => plan.readiness === 'READY').length} ready · {plans.filter(plan => plan.readiness === 'BLOCKED').length} blocked by missing prerequisites.</p><button className="button secondary" onClick={() => onOpenPlans(hypothesis.id)}>Inspect test plan <span aria-hidden="true">→</span></button></> : <p>No test draft is available for the current method and context. Review analysis notes for planning limits.</p>}</section>
    <section className="inspector-section"><h3>Evidence trail</h3>{hypothesis.evidence.map(item => <details className="investigation-evidence" key={item.id}><summary>{readable(item.kind)}<span>{item.producerId}</span></summary><p>{item.summary}</p><dl><dt>Recorded</dt><dd>{date(item.capturedAt)}</dd><dt>Reference</dt><dd className="mono">{item.id}</dd></dl></details>)}</section>
    <Limitations items={hypothesis.limitations} />
  </article>;
}

function PlanDetail({ plan, hypothesis, headingRef }: { plan: InvestigationPlan; hypothesis: InvestigationHypothesis | undefined; headingRef: HeadingRef }) {
  return <article><div className="inspector-meta"><span className={`readiness ${plan.readiness.toLowerCase()}`}>{plan.readiness === 'READY' ? 'Planning ready' : 'Planning blocked'}</span><span className="badge neutral">Not run</span></div><h2 ref={headingRef} tabIndex={-1}>{plan.title}</h2>{hypothesis?.endpoint && <p className="inspector-route mono"><span>{hypothesis.endpoint.method}</span> {hypothesis.endpoint.path}</p>}
    <section className="inspector-section"><h3>{plan.prerequisites.length ? 'What this plan needs' : 'Planning prerequisites are present'}</h3>{plan.prerequisites.length ? <ul className="prerequisite-list">{plan.prerequisites.map((item, index) => <li key={index}><span className="prerequisite-marker" aria-hidden="true">!</span><div><p>{requirements[item.code] ?? readable(item.code)}</p>{item.parameter && <code>{item.parameter.location} · {item.parameter.name}</code>}</div></li>)}</ul> : <p>The plan has its planning inputs. An execution host must still check policy, scope, and available tools.</p>}</section>
    <section className="inspector-section"><h3>Planned sequence</h3><ol className="plan-sequence">{plan.steps.map((step, index) => <li key={step.id}><span className="plan-step-number" aria-hidden="true">{index + 1}</span><div><h4>{actions[step.action] ?? readable(step.action)}</h4><p>{step.expectedObservation}</p>{step.dependsOn.length > 0 && <span className="step-dependency">After {step.dependsOn.map(id => `step ${plan.steps.findIndex(item => item.id === id) + 1}`).join(', ')}</span>}</div></li>)}</ol></section>
    <section className="inspector-section"><h3>Verification requirements</h3><p>The {readable(plan.verification.strategy)} rule will need these observations:</p><ul className="verification-list">{plan.verification.evidenceRequirements.map(item => <li key={item}>{readable(item)}</li>)}</ul></section>
    <section className="inspector-section"><h3>Required capabilities</h3><div className="tag-list">{plan.requiredCapabilities.map(item => <span className="tag" key={item}>{readable(item)}</span>)}</div>{plan.optionalCapabilities.length > 0 && <details className="optional-capabilities"><summary>Optional capabilities</summary><div className="tag-list">{plan.optionalCapabilities.map(item => <span className="tag" key={item}>{readable(item)}</span>)}</div></details>}<p className="help-text">Capabilities are requirements. Runtime execution is not configured in this workspace.</p></section>
    <Limitations items={plan.limitations} />
  </article>;
}

function Limitations({ items }: { items: readonly string[] }) {
  return items.length ? <details className="investigation-limitations"><summary>Limits of this result</summary><ul>{items.map(item => <li key={item}>{item}</li>)}</ul></details> : null;
}
function Coverage({ snapshot }: { snapshot: InvestigationSnapshot }) {
  return <details className="surface coverage-panel" open={snapshot.state === 'unavailable'}><summary><span>Supported checks</span><span>{snapshot.coverage.length} CWE rules · {new Set(snapshot.coverage.map(item => item.probeId)).size} probe families</span></summary><div className="coverage-intro"><p>Registered rules can generate questions and plans from relevant observations. Runtime execution is not configured. Zero candidates means no grounded question was generated from the available context.</p></div><div className="table-scroll"><table className="data-table coverage-table"><caption className="screen-reader-only">Registered rules and planning coverage</caption><thead><tr><th scope="col">Weakness</th><th scope="col">Probe family</th><th scope="col">Hypotheses</th><th scope="col">Plans</th><th scope="col">Runtime</th></tr></thead><tbody>{snapshot.coverage.map(item => <tr key={item.cweId}><td><strong>{item.title}</strong><span>{item.cweId}</span></td><td>{readable(item.probeId)}</td><td>{snapshot.hypotheses.filter(hypothesis => hypothesis.cweId === item.cweId).length}</td><td>{snapshot.plans.filter(plan => plan.cweId === item.cweId).length}</td><td><span className="badge neutral">Not configured</span><details><summary>Capabilities needed</summary><p>{item.requiredCapabilities.map(readable).join(', ')}</p></details></td></tr>)}</tbody></table></div></details>;
}
