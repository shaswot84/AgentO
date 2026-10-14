import { describe, expect, it, vi } from 'vitest';
import type { AnalysisContext, BrowserAction, Persona, TargetApplicationProfile } from '@agento/core';
import {
  TesterArmyE2EAdapter,
  createPortalProfile,
  portalBrowserOptions,
  PortalWorkflowPlanner,
  createEdgeSpaProfile,
  edgeSpaBrowserOptions,
  EdgeSpaWorkflowPlanner,
  EdgeMultiStepStrategy,
} from '../src/index.js';
import { context, fakeRuntime, workflow } from './helpers.js';

describe('Portal (Demo App 03) target profile and planning', () => {
  const origin = context.project.baseUrl;
  const profile = createPortalProfile([origin]);
  const planner = new PortalWorkflowPlanner();

  it('declares personas, session-cookie auth, and HTML 302 form redirect configuration', () => {
    expect(profile.personas?.map(p => p.id)).toEqual(['analyst', 'admin']);
    expect(profile.personas?.every(p => p.authentication === 'session-cookie')).toBe(true);
    expect(profile.defaultAuthenticationStrategyId).toBe('portal-form');

    const strategy = profile.authentication?.find(s => s.id === 'portal-form');
    expect(strategy).toBeDefined();
    const prep = strategy!.prepare(profile.personas![0]!);
    expect(prep.verification.expectedIdentity).toBe('analyst');
    expect('identitySelector' in prep.verification).toBe(true);
    expect(prep.actions!.some(a => 'response' in a && a.response?.status === 302)).toBe(true);
  });

  it('plans navigation to reports when on dashboard and clicks open latest report', async () => {
    const inputBase = {
      workflow: { id: 'audit-goal', identityId: 'analyst', goal: 'open latest report' },
      target: profile,
      actionCount: 0,
      executedActions: 0,
      persona: profile.personas![0]!,
      contextIdentities: profile.personas!,
    };

    const dashboardStep = await planner.next({
      ...inputBase,
      page: { url: `${origin}/dashboard`, controls: [] },
    });
    expect(dashboardStep).toEqual({
      outcome: 'action',
      action: { action: 'navigate', url: '/reports', response: { url: '/reports', method: 'GET', status: 200 } },
    });

    const reportsStep = await planner.next({
      ...inputBase,
      page: {
        url: `${origin}/reports`,
        controls: [{ selector: 'a#open-report-btn', kind: 'link', label: 'Open latest report', href: `${origin}/reports/REP-501` }],
      },
    });
    expect(reportsStep).toEqual({
      outcome: 'action',
      action: { action: 'click', selector: 'a#open-report-btn', response: { url: '/reports/*', method: 'GET', status: 200 } },
    });

    const detailStep = await planner.next({
      ...inputBase,
      page: { url: `${origin}/reports/REP-501`, controls: [] },
    });
    expect(detailStep).toEqual({ outcome: 'complete' });
  });
});

describe('Edge SPA (Demo App 04) target profile, multi-step auth, and boundaries', () => {
  const origin = context.project.baseUrl;
  const multiProfile = createEdgeSpaProfile([origin], 'edge-spa', 'edge-multi-step');
  const singleProfile = createEdgeSpaProfile([origin], 'edge-spa', 'edge-single-step');
  const planner = new EdgeSpaWorkflowPlanner();

  it('declares operator personas and supports both multi-step and single-step strategies', () => {
    expect(multiProfile.personas?.map(p => p.id)).toEqual(['operator', 'supervisor']);
    expect(multiProfile.authentication?.map(s => s.id)).toEqual(['edge-multi-step', 'edge-single-step']);
  });

  it('prepares multi-step sequence with lookup, reveal wait, and login submit', () => {
    const multiStrategy = multiProfile.authentication!.find(s => s.id === 'edge-multi-step')!;
    const prep = multiStrategy.prepare(multiProfile.personas![0]!);
    expect(prep.actions!).toHaveLength(7);
    expect(prep.actions![0]).toEqual({ action: 'navigate', url: '/login' });
    expect(prep.actions![1]).toEqual({ action: 'fill-credential', selector: '#identifier', field: 'username' });
    expect(prep.actions![2]).toEqual({
      action: 'click',
      selector: '#btn-next',
      response: { url: '/api/auth/lookup*', method: 'GET', status: 200 },
    });
    expect(prep.actions![3]).toEqual({ action: 'wait-visible', selector: '#password' });
    expect(prep.actions![4]).toEqual({ action: 'fill-credential', selector: '#password', field: 'password' });
    expect(prep.actions![5]).toEqual({
      action: 'click',
      selector: '#btn-submit',
      response: { url: '/api/auth/login', method: 'POST', status: 200 },
    });
  });

  it('plans telemetry button click from workspace and detects completion', async () => {
    const inputBase = {
      workflow: { id: 'telemetry-goal', identityId: 'operator', goal: 'open latest telemetry' },
      target: multiProfile,
      actionCount: 0,
      executedActions: 0,
      persona: multiProfile.personas![0]!,
      contextIdentities: multiProfile.personas!,
    };

    const actionStep = await planner.next({
      ...inputBase,
      page: {
        url: `${origin}/workspace`,
        controls: [{ selector: 'button#btn-load-telemetry', kind: 'button', label: 'Open latest telemetry' }],
      },
    });
    expect(actionStep).toEqual({
      outcome: 'action',
      action: {
        action: 'click',
        selector: 'button#btn-load-telemetry',
        response: { url: '/api/telemetry/*', method: 'GET', status: 200 },
      },
    });

    const completeStep = await planner.next({
      ...inputBase,
      page: { url: `${origin}/workspace`, controls: [] },
    });
    expect(completeStep).toEqual({ outcome: 'complete' });
  });

  it('runs multi-step flow against fake runtime with credentials injected', async () => {
    const runtime = fakeRuntime();
    const originalStart = runtime.start.getMockImplementation()!;
    runtime.start.mockImplementation(async request => {
      const session = await originalStart(request);
      return {
        ...session,
        inspect: async () => ({ url: `${request.project.baseUrl}/workspace`, controls: [] }),
      };
    });
    const options = edgeSpaBrowserOptions([origin]);
    const ctx: AnalysisContext = {
      ...context,
      identities: multiProfile.personas!,
    };
    const result = await new TesterArmyE2EAdapter({ ...options, runtime }).observe(ctx, {
      id: 'test-multistep',
      identityId: 'operator',
      goal: 'open latest telemetry',
    });
    expect(result.outcome).toBe('COMPLETED');
    expect(runtime.start).toHaveBeenCalledOnce();
    const performed = runtime.sessions[0]!.perform.mock.calls.map(([a]) => a);
    expect(performed).toContainEqual({ action: 'fill', selector: '#identifier', value: 'operator' });
    expect(performed).toContainEqual({ action: 'fill', selector: '#password', value: 'Operator!42' });
  });
});
