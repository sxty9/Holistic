import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@finessefx/ui/styles.css';
import { App } from './App';
import { Gate } from './Gate';
import { Status } from './Status';
import * as api from './api';
import type { State } from './api';

/**
 * Three screens and one rule for choosing between them: ask the server.
 *
 * Which screen to show is a fact about the machine, not about this tab. A page
 * that decided for itself — from a cookie it can read, or from something it put
 * in localStorage — would show the wizard to somebody whose session had been
 * cleared, and would keep showing it after the instance was sealed.
 */
function Root() {
  const [state, setState] = useState<State | null>(null);
  const [gated, setGated] = useState(false);
  const [error, setError] = useState('');

  const load = () =>
    api
      .getState()
      .then((s) => {
        setState(s);
        setGated(false);
      })
      .catch((e) => {
        if (e instanceof api.ApiError && (e.status === 401 || e.status === 403)) {
          setGated(true);
          return;
        }
        setError(e instanceof Error ? e.message : String(e));
      });

  useEffect(() => {
    void load();
  }, []);

  if (gated) return <Gate onClaimed={() => void load()} />;
  if (error) {
    return (
      <div style={{ maxWidth: 640, margin: '0 auto', padding: 'var(--space-7) var(--space-5)' }}>
        <h1 style={{ fontSize: 'var(--text-title)' }}>This page could not read the machine's state</h1>
        {/* Verbatim, not summarised. The one time this matters, the exact
            words are what somebody will search for. */}
        <pre className="fx-mono fx-scroll-x" style={{ whiteSpace: 'pre-wrap' }}>{error}</pre>
      </div>
    );
  }
  if (!state) return null;
  if (state.sealed) return <Status state={state} />;
  return <App initial={state} />;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
