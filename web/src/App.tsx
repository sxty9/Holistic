import { useCallback, useEffect, useState } from 'react';
import { Banner, Button, Card, EmptyState, Stepper } from '@finessefx/ui';
import * as api from './api';
import type { State, Step } from './api';
import { ConflictReport } from './Conflict';
import { NeedsForm } from './Needs';
import { current, observe } from './ledger';

/**
 * The wizard.
 *
 * Two halves: the ledger on the left, the step being worked on the right. The
 * ledger is a record and the panel is the work, and keeping them apart is what
 * lets somebody read a row from an hour ago without the page scrolling away
 * from them when the machine moves on.
 *
 * The tab that starts the switch finishes it. Nothing here ever navigates to
 * the new domain: the two slowest links — the registrar's nameservers and
 * Cloudflare's certificate — run on somebody else's clock and can outlive a
 * session, and a wizard that hands off mid-flight has no way to report what
 * happened next.
 */
export function App({ initial }: { initial: State }) {
  const [state, setState] = useState(initial);
  const [selected, setSelected] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const act = useCallback(async (fn: () => Promise<State>) => {
    setBusy(true);
    setError('');
    try {
      setState(await fn());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  // A slow poll, and only while something is on somebody else's clock. Not a
  // progress bar and not a stream: the ledger is a file, this is a re-read of
  // it, and the page says when it last looked rather than pretending to know
  // sooner than that.
  const waiting = state.steps.some((s) => s.status === 'running' || s.status === 'waiting_on_them');
  useEffect(() => {
    if (!waiting || busy) return;
    const t = setInterval(() => {
      api.getState().then(setState).catch(() => {
        /* A failed re-read is not news. The last good read stays on screen with
           its own timestamp, which is more honest than blanking the page. */
      });
    }, 5000);
    return () => clearInterval(t);
  }, [waiting, busy]);

  const open = state.steps.find((s) => s.id === selected) ?? current(state);
  const rows = observe(state, { onRun: () => {}, onCopy: () => {} }, (s: Step) => (
    <Button size="sm" disabled={busy} onClick={() => act(() => api.runStep(s.id))}>
      Run this
    </Button>
  ));

  return (
    <div
      style={{
        display: 'grid',
        gap: 'var(--space-6)',
        gridTemplateColumns: 'minmax(320px, 460px) 1fr',
        alignItems: 'start',
        maxWidth: 'var(--shell-max)',
        margin: '0 auto',
        padding: 'var(--space-6)',
      }}
    >
      <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
        {state.refused > 0 ? (
          <Banner tone="alert" title={`${state.refused} wrong setup code${state.refused === 1 ? '' : 's'} were offered`}>
            {/* Whoever has been probed should be told, and on the first screen
                rather than in a log they will never open. */}
            {state.refusedFrom?.length ? `From: ${state.refusedFrom.join(', ')}.` : null} If none of
            those were you, someone else on this network tried to claim this machine.
          </Banner>
        ) : null}

        <Stepper
          observations={rows}
          readAt={state.readAt}
          selected={selected}
          onSelect={(id) => setSelected(id === selected ? undefined : id)}
        />

        {state.resources.length > 0 ? <Resources state={state} /> : null}
      </div>

      <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
        {error ? (
          <Banner tone="alert" title="That did not work" onDismiss={() => setError('')}>
            {error}
          </Banner>
        ) : null}
        {open ? <Panel step={open} busy={busy} act={act} /> : <Finished />}
      </div>
    </div>
  );
}

function Panel({
  step,
  busy,
  act,
}: {
  step: Step;
  busy: boolean;
  act: (fn: () => Promise<State>) => Promise<void>;
}) {
  if (step.status === 'conflict' && step.conflict) {
    return (
      <ConflictReport
        conflict={step.conflict}
        onRecheck={() => act(() => api.runStep(step.id))}
        onSkip={() => act(() => api.skipStep(step.id, 'skipped from the conflict report'))}
      />
    );
  }

  if (step.needs) {
    return (
      <NeedsForm
        needs={step.needs}
        busy={busy}
        onSubmit={(v) => act(() => api.answer(step.id, v))}
        onRecheck={() => act(() => api.runStep(step.id))}
      />
    );
  }

  return (
    <Card pad="lg" style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <div>
        <div className="fx-label">{step.title}</div>
        {step.desired ? <p style={{ marginTop: 'var(--space-2)' }}>{step.desired}</p> : null}
        {step.detail ? (
          <p style={{ marginTop: 'var(--space-2)', color: 'var(--text-secondary)' }}>{step.detail}</p>
        ) : null}
      </div>
      {step.status === 'waiting_on_them' ? (
        // No button. Pressing one would not make a registrar go faster, and a
        // button that does nothing teaches people that buttons here do nothing.
        <p style={{ color: 'var(--text-secondary)' }}>
          This is on {step.waitingOn ?? 'someone else'}'s clock. It is being checked; nothing here
          makes it sooner.
        </p>
      ) : (
        <div>
          <Button variant="primary" disabled={busy} onClick={() => act(() => api.runStep(step.id))}>
            Run this step
          </Button>
        </div>
      )}
    </Card>
  );
}

function Resources({ state }: { state: State }) {
  const open = state.resources.filter((r) => !r.confirmed);
  return (
    <Card inset pad="md" style={{ display: 'grid', gap: 'var(--space-3)' }}>
      <div className="fx-label">Created outside this machine</div>
      {state.resources.map((r) => (
        <div key={`${r.provider}/${r.kind}/${r.ref}`} className="fx-mono" style={{ fontSize: 'var(--text-caption)' }}>
          {r.provider} {r.kind} {r.ref}
          {r.confirmed ? '' : '  — not confirmed'}
        </div>
      ))}
      {open.length > 0 ? (
        // An entry that stays unconfirmed is how an interrupted apply is found
        // rather than forgotten. It is the line worth a person's attention.
        <p style={{ color: 'var(--text-secondary)' }}>
          {open.length} of these were asked for and never acknowledged. If setup was interrupted,
          they may exist at the provider without this machine knowing.
        </p>
      ) : null}
    </Card>
  );
}

function Finished() {
  return (
    <EmptyState
      icon="check-circle"
      title="Every step has been dealt with"
      detail="Nothing is left pending. Close this tab; signing in happens on your own domain from now on."
    />
  );
}
