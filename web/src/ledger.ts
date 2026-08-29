import type { Observation } from '@finessefx/ui';
import type { State, Step } from './api';

// The mapping from the ledger onto the Stepper, and the reasons for the two
// places it is not one to one. docs/setup-api.md carries the same table; this
// is the executable half of it.
//
// The Stepper has no state for "the machine is working". That is on purpose,
// not an omission: its rule is that an unattributed wait reads as this being
// slow, so every wait has to name whose clock it is on. "We are working" is a
// wait like any other, and it names this machine.
//
// `skipped` becomes `yours` rather than `passed` or `ahead`, because a skipped
// step is not blocked and it is not finished — it is not done, and you own
// whether it happens. The row carries the control that runs it.

export interface Handlers {
  onRun(id: string): void;
  onCopy(text: string): void;
}

export function observe(state: State, h: Handlers, act: (s: Step) => React.ReactNode): Observation[] {
  return state.steps.map((s) => row(s, state, h, act));
}

function row(s: Step, state: State, _h: Handlers, act: (s: Step) => React.ReactNode): Observation {
  const label = s.title;
  switch (s.status) {
    case 'pending':
      return { state: 'ahead', id: s.id, label, desired: s.desired };

    case 'running':
      return {
        state: 'waiting',
        id: s.id,
        label,
        waitingOn: 'this machine',
        since: s.since ?? state.readAt,
        lastLooked: state.readAt,
        detail: s.detail,
      };

    case 'waiting_on_them':
      return {
        state: 'waiting',
        id: s.id,
        label,
        // Never a bare "waiting". If the server did not name whom, say that it
        // did not — an unnamed wait is a fact about our own instrumentation and
        // the reader should see which one they are looking at.
        waitingOn: s.waitingOn ?? 'someone this step did not name',
        since: s.since ?? state.readAt,
        lastLooked: s.lastLooked ?? state.readAt,
        detail: s.detail,
      };

    case 'passed':
      // `actual` is the proof, verbatim. A step proven by an end-to-end
      // observation shows the observation; one that passed on a 200 shows that
      // it was only a 200. The difference is the whole reason the field exists.
      return { state: 'passed', id: s.id, label, at: s.at ?? state.readAt, actual: s.proof };

    case 'failed':
      return {
        state: 'failed',
        id: s.id,
        label,
        at: s.at ?? state.readAt,
        output: s.detail,
        action: act(s),
      };

    case 'conflict':
      return {
        state: 'held',
        id: s.id,
        label,
        at: s.at ?? state.readAt,
        found: s.conflict?.found,
        desired: s.conflict?.desired,
        // The instruction, not the reason. The reason is in the panel; the row
        // says the one thing to do.
        resolution: s.conflict?.resolution ?? 'Open this row to see what is in the way.',
      };

    case 'skipped':
      return {
        state: 'yours',
        id: s.id,
        label,
        detail: s.detail ?? 'Skipped. Nothing depends on it having run.',
        action: act(s),
      };
  }
}

/** The step the wizard is actually on: the first that is not finished. Not the
 *  row the reader has open — those are different questions and conflating them
 *  is how a wizard scrolls away from what somebody is reading. */
export function current(state: State): Step | undefined {
  return state.steps.find((s) => s.status !== 'passed' && s.status !== 'skipped');
}
