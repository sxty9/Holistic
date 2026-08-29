import { useEffect, useState } from 'react';
import { Button, Card, Checkbox, Input, KeyValue, SegmentedControl } from '@finessefx/ui';
import type { Needs as NeedsShape } from './api';
import { copyText } from './copy';

/**
 * Renders what a step is asking for, without knowing what the step means.
 *
 * That ignorance is the point. A page that knows the domain step is special
 * grows a branch per step, and the sixteenth one is written by somebody who has
 * stopped reading the first fifteen. Here a step is a shape, and a shape it has
 * never seen renders as well as one it has.
 */
export function NeedsForm({
  needs,
  busy,
  onSubmit,
  onRecheck,
}: {
  needs: NeedsShape;
  busy: boolean;
  onSubmit: (value: unknown) => void;
  onRecheck: () => void;
}) {
  switch (needs.kind) {
    case 'text':
      return <TextNeed needs={needs} busy={busy} onSubmit={onSubmit} />;
    case 'choice':
      return <ChoiceNeed needs={needs} busy={busy} onSubmit={onSubmit} />;
    case 'apps':
      return <AppsNeed needs={needs} busy={busy} onSubmit={onSubmit} />;
    case 'secret':
      return <SecretNeed needs={needs} busy={busy} onSubmit={onSubmit} />;
    case 'confirm':
      return <ConfirmNeed needs={needs} busy={busy} onSubmit={onSubmit} />;
    case 'manual':
      return <ManualNeed needs={needs} busy={busy} onRecheck={onRecheck} />;
  }
}

function Frame({ label, help, children }: { label: string; help?: string; children: React.ReactNode }) {
  return (
    <Card pad="lg" style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <div>
        <div className="fx-label">{label}</div>
        {help ? <p style={{ marginTop: 'var(--space-2)', color: 'var(--text-secondary)' }}>{help}</p> : null}
      </div>
      {children}
    </Card>
  );
}

function TextNeed({ needs, busy, onSubmit }: { needs: Extract<NeedsShape, { kind: 'text' }>; busy: boolean; onSubmit: (v: unknown) => void }) {
  const [v, setV] = useState(needs.value ?? '');
  useEffect(() => setV(needs.value ?? ''), [needs.value]);
  return (
    <Frame label={needs.label} help={needs.help}>
      <Input label={needs.label} value={v} onChange={setV} placeholder={needs.placeholder} />
      <div>
        <Button variant="primary" disabled={busy || v.trim() === ''} onClick={() => onSubmit(v.trim())}>
          Save
        </Button>
      </div>
    </Frame>
  );
}

function ChoiceNeed({ needs, busy, onSubmit }: { needs: Extract<NeedsShape, { kind: 'choice' }>; busy: boolean; onSubmit: (v: unknown) => void }) {
  const [v, setV] = useState(needs.value ?? needs.options[0]?.value ?? '');
  return (
    <Frame label={needs.label} help={needs.help}>
      <SegmentedControl options={needs.options} value={v} onChange={setV} />
      <div>
        <Button variant="primary" disabled={busy} onClick={() => onSubmit(v)}>
          Save
        </Button>
      </div>
    </Frame>
  );
}

function AppsNeed({ needs, busy, onSubmit }: { needs: Extract<NeedsShape, { kind: 'apps' }>; busy: boolean; onSubmit: (v: unknown) => void }) {
  const [on, setOn] = useState<Record<string, boolean>>(
    Object.fromEntries(needs.options.map((o) => [o.id, o.on])),
  );
  return (
    <Frame label={needs.label} help={needs.help}>
      <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
        {needs.options.map((o) => (
          <div key={o.id}>
            <Checkbox
              label={o.label}
              checked={on[o.id] ?? false}
              onChange={(c) => setOn((p) => ({ ...p, [o.id]: c }))}
            />
            {o.detail ? (
              <div style={{ marginLeft: 'var(--space-6)', color: 'var(--text-muted)' }}>{o.detail}</div>
            ) : null}
          </div>
        ))}
      </div>
      <div>
        <Button
          variant="primary"
          disabled={busy}
          onClick={() => onSubmit(needs.options.filter((o) => on[o.id]).map((o) => o.id))}
        >
          Save
        </Button>
      </div>
    </Frame>
  );
}

function SecretNeed({ needs, busy, onSubmit }: { needs: Extract<NeedsShape, { kind: 'secret' }>; busy: boolean; onSubmit: (v: unknown) => void }) {
  const [v, setV] = useState('');
  return (
    <Frame label={needs.label} help={needs.help}>
      {needs.link ? (
        <p>
          <a href={needs.link} target="_blank" rel="noreferrer noopener">
            {needs.linkLabel ?? 'Open the form with the right boxes already ticked'}
          </a>
        </p>
      ) : null}
      <Input label={needs.label} value={v} onChange={setV} />
      {/* Cleared from this component the moment it is submitted. It is never
          read back from the server either — a masked secret in a JSON response
          is still a secret in a browser's memory and in a proxy's log. */}
      <div>
        <Button
          variant="primary"
          disabled={busy || v.trim() === ''}
          onClick={() => {
            const s = v.trim();
            setV('');
            onSubmit(s);
          }}
        >
          Hand it over
        </Button>
      </div>
    </Frame>
  );
}

function ConfirmNeed({ needs, busy, onSubmit }: { needs: Extract<NeedsShape, { kind: 'confirm' }>; busy: boolean; onSubmit: (v: unknown) => void }) {
  return (
    <Frame label={needs.label} help={needs.help}>
      {/* Every line of what is about to change, before it changes. This is the
          last free stop, and it is free only if it is complete. */}
      <KeyValue
        items={needs.changes.map((c) => ({
          label: c.path,
          value: (
            <span className="fx-mono">
              {c.from === '' ? <em style={{ color: 'var(--text-muted)' }}>not set</em> : c.from}
              {' → '}
              {c.to}
            </span>
          ),
        }))}
      />
      <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
        {/* Default is no. The affirmative is the one that has to be chosen. */}
        <Button variant="primary" disabled={busy} onClick={() => onSubmit(true)}>
          Apply these {needs.changes.length} change{needs.changes.length === 1 ? '' : 's'}
        </Button>
      </div>
    </Frame>
  );
}

function ManualNeed({ needs, busy, onRecheck }: { needs: Extract<NeedsShape, { kind: 'manual' }>; busy: boolean; onRecheck: () => void }) {
  return (
    <Frame label={needs.label}>
      <pre
        className="fx-mono fx-scroll-x"
        style={{
          padding: 'var(--space-4)',
          background: 'var(--surface-well)',
          boxShadow: 'var(--shadow-inset-sm)',
          borderRadius: 'var(--radius-md)',
          whiteSpace: 'pre-wrap',
        }}
      >
        {needs.instructions}
      </pre>
      <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
        {/* "Check again" and nothing else. There is no continue-anyway for a
            thing a third party has not done yet. */}
        {needs.recheck !== false ? (
          <Button variant="primary" disabled={busy} onClick={onRecheck}>
            Check again
          </Button>
        ) : null}
        <Button variant="ghost" onClick={() => copyText(needs.instructions)}>
          Copy
        </Button>
      </div>
    </Frame>
  );
}
