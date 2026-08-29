import { Card, KeyValue } from '@finessefx/ui';
import type { State } from './api';

/**
 * What this address serves once the instance is claimed.
 *
 * Not a login form. After the switch the session cookie is scoped to the real
 * domain and marked Secure, so it would be neither sent to nor accepted from
 * this page — a form here could not work, and a form that cannot work is worse
 * than a sentence that explains why.
 *
 * The address keeps resolving on purpose. It is the way back into the machine
 * when the tunnel breaks, the domain lapses or the account is suspended. A home
 * server whose only route to itself runs through a third party's edge has
 * exactly the single point of failure the whole design avoids.
 */
export function Status({ state }: { state: State }) {
  return (
    <div style={{ maxWidth: 640, margin: '0 auto', padding: 'var(--space-7) var(--space-5)' }}>
      <Card pad="lg" style={{ display: 'grid', gap: 'var(--space-5)' }}>
        <div>
          <h1 style={{ fontSize: 'var(--text-title)' }}>This instance is set up</h1>
          <p style={{ marginTop: 'var(--space-3)', color: 'var(--text-secondary)' }}>
            Signing in happens on your own domain. This address stays reachable on your network as a
            way back in if the tunnel ever stops.
          </p>
        </div>
        <KeyValue
          items={[
            { label: 'Domain', value: state.domain ?? '—' },
            { label: 'Read at', value: state.readAt },
            { label: 'Steps recorded', value: String(state.steps.length) },
          ]}
        />
        <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-caption)' }}>
          To change the configuration, sign in at your domain. To re-open setup deliberately, do it
          on the machine — never over the network.
        </p>
      </Card>
    </div>
  );
}
