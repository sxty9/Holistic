import { useState } from 'react';
import { Banner, Button, Card, Input } from '@finessefx/ui';
import * as api from './api';

/**
 * The one screen shown before a session exists.
 *
 * The code is typed, never pasted from a URL: a code in a query string is in
 * the server's log, in the browser's history, and in the Referer header of the
 * next request the page makes.
 *
 * There is no password field here and there never will be. This page is served
 * over plain HTTP on a name any machine on the network can claim, so a password
 * typed here would be saved by the reader's manager against an origin that
 * every Holistic instance in the world shares — and offered back to them on
 * somebody else's machine, in somebody else's house. The administrator is
 * created through the shell that installed this.
 */
export function Gate({ onClaimed }: { onClaimed: () => void }) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit() {
    setBusy(true);
    setError('');
    try {
      await api.redeem(code);
      onClaimed();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The code was not accepted.');
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 520, margin: '0 auto', padding: 'var(--space-7) var(--space-5)' }}>
      <Card pad="lg" style={{ display: 'grid', gap: 'var(--space-5)' }}>
        <div>
          <h1 style={{ fontSize: 'var(--text-title)' }}>This machine is not claimed yet</h1>
          <p style={{ marginTop: 'var(--space-3)', color: 'var(--text-secondary)' }}>
            The installer printed a setup code in the terminal it ran in. Type it here. It proves you
            are the person who installed this, and it works once.
          </p>
        </div>

        {error ? <Banner tone="alert" title="Not accepted">{error}</Banner> : null}

        <Input
          label="Setup code"
          value={code}
          onChange={setCode}
          placeholder="abcde-fghij-klmno-pqrst"
          mono
        />

        <div>
          <Button variant="primary" disabled={busy || code.trim() === ''} onClick={submit}>
            Claim this machine
          </Button>
        </div>

        <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-caption)' }}>
          Lost it? On the machine itself: <code className="fx-mono">sudo holistic code</code>. It
          cannot be re-sent from here — that is the point of it.
        </p>
      </Card>
    </div>
  );
}
