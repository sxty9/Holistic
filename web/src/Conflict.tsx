import { Banner, Button, Card, KeyValue } from '@finessefx/ui';
import type { Conflict as ConflictShape } from './api';
import { copyText } from './copy';

/**
 * The six fields, always in this order, values quoted rather than paraphrased.
 *
 * The order is the argument: what the object is, what is already there, what
 * this wanted, why the two cannot both be true, that nothing was changed, and
 * only then what to do. Reordered, it reads as a demand.
 *
 * There is deliberately no way past a conflict from in here. Not "continue
 * anyway", not an automatically renamed worker, not a second SPF record. The
 * goal is not to get past the obstacle — it is to leave the operator's own
 * things alone, which is the whole product promise.
 */
export function ConflictReport({
  conflict,
  onRecheck,
  onSkip,
}: {
  conflict: ConflictShape;
  onRecheck: () => void;
  onSkip: () => void;
}) {
  const instructions = conflict.resolution;

  return (
    <Card pad="lg" style={{ display: 'grid', gap: 'var(--space-5)' }}>
      <Banner tone="warn" title="Something is already here">
        {/* Its own line, in every conflict. A promise stated inside a
            paragraph is a promise nobody read. */}
        <strong>Holistic has not changed anything.</strong>
      </Banner>

      <KeyValue
        items={[
          { label: 'Object', value: <code>{conflict.object}</code> },
          {
            label: 'Yours',
            value: (
              <span>
                <code>{conflict.found}</code>
                {conflict.foundNote ? (
                  <span style={{ display: 'block', color: 'var(--text-muted)' }}>{conflict.foundNote}</span>
                ) : null}
              </span>
            ),
          },
          { label: 'Wanted', value: <code>{conflict.desired}</code> },
        ]}
      />

      <div>
        <div className="fx-label">Why it collides</div>
        <p style={{ marginTop: 'var(--space-2)' }}>{conflict.why}</p>
      </div>

      <div>
        <div className="fx-label">To continue, do this yourself and check again</div>
        <pre
          className="fx-mono fx-scroll-x"
          style={{
            marginTop: 'var(--space-2)',
            padding: 'var(--space-4)',
            background: 'var(--surface-well)',
            boxShadow: 'var(--shadow-inset-sm)',
            borderRadius: 'var(--radius-md)',
            whiteSpace: 'pre-wrap',
          }}
        >
          {instructions}
        </pre>
      </div>

      {conflict.consequence ? (
        <p style={{ color: 'var(--text-secondary)' }}>
          If you skip this: {conflict.consequence}
        </p>
      ) : null}

      <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
        <Button variant="primary" onClick={onRecheck}>
          Check again
        </Button>
        <Button onClick={onSkip}>Skip this step</Button>
        <Button variant="ghost" onClick={() => copyText(instructions)}>
          Copy the instructions
        </Button>
      </div>
    </Card>
  );
}
