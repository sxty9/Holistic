// The wire, exactly as docs/setup-api.md defines it.
//
// These types are hand-written against that document rather than generated from
// the Go, and that is deliberate: the document is the contract, and two
// implementations that both read it will disagree loudly, where one generated
// from the other would agree silently and both be wrong together.

/** Where a step stands. Seven, and the distinction that matters most is between
 *  `running` and `waiting_on_them`: "we are working" and "a registrar is
 *  working" feel identical in a spinner and are completely different facts. */
export type Status =
  | 'pending'
  | 'running'
  | 'waiting_on_them'
  | 'passed'
  | 'failed'
  | 'conflict'
  | 'skipped';

/** Who has to act. It decides whether a step can run unattended. */
export type Kind = 'local' | 'shell' | 'foreign' | 'theirs';

export type Needs =
  | { kind: 'text'; label: string; placeholder?: string; help?: string; value?: string }
  | { kind: 'choice'; label: string; help?: string; options: Option[]; value?: string }
  | { kind: 'apps'; label: string; help?: string; options: AppChoice[] }
  | { kind: 'secret'; label: string; help?: string; link?: string; linkLabel?: string }
  | { kind: 'confirm'; label: string; help?: string; changes: Change[] }
  | { kind: 'manual'; label: string; instructions: string; recheck?: boolean };

export interface Option { value: string; label: string; detail?: string }
export interface AppChoice { id: string; label: string; detail?: string; on: boolean }
export interface Change { path: string; from: string; to: string }

/** The six fields of a conflict, always in this order. */
export interface Conflict {
  object: string;
  found: string;
  foundNote?: string;
  desired: string;
  why: string;
  resolution: string;
  consequence?: string;
}

export interface Step {
  id: string;
  title: string;
  kind: Kind;
  status: Status;
  detail?: string;
  /** How this was shown to be true. An API returning 200 records that; an
   *  end-to-end observation records the observation and its nonce. */
  proof?: string;
  at?: string;
  /** Since when it has been waiting, and on whom. Only on a wait. */
  since?: string;
  waitingOn?: string;
  lastLooked?: string;
  /** What it will do, for a step that has not run. */
  desired?: string;
  needs?: Needs;
  conflict?: Conflict;
}

/** Something that exists at a provider because of this machine. One that stays
 *  unconfirmed is how an interrupted apply is found rather than forgotten. */
export interface Resource {
  provider: string;
  kind: string;
  ref: string;
  note?: string;
  intended: string;
  confirmed?: string;
}

export interface State {
  readAt: string;
  sealed: boolean;
  domain?: string;
  steps: Step[];
  resources: Resource[];
  /** Wrong setup codes offered before the right one. Someone who has been
   *  probed should be told, on the first screen. */
  refused: number;
  refusedFrom?: string[];
}

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function call(path: string, init?: RequestInit): Promise<State> {
  const res = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    // The session cookie is the only credential and it is same-origin. Saying
    // so explicitly keeps a future proxy from being handed one by accident.
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new ApiError(res.status, body.trim() || `${res.status} ${res.statusText}`);
  }
  return (await res.json()) as State;
}

export const getState = () => call('/api/state');
export const runStep = (id: string) => call(`/api/step/${encodeURIComponent(id)}/run`, { method: 'POST' });
export const skipStep = (id: string, reason: string) =>
  call(`/api/step/${encodeURIComponent(id)}/skip`, { method: 'POST', body: JSON.stringify({ reason }) });
export const answer = (id: string, value: unknown) =>
  call(`/api/answer/${encodeURIComponent(id)}`, { method: 'POST', body: JSON.stringify({ value }) });

/** Redeem the setup code. Not a State call: it is the one request made before a
 *  session exists, and its only outcome that matters is whether one now does. */
export async function redeem(code: string): Promise<void> {
  const body = new URLSearchParams({ code });
  const res = await fetch('/claim/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (!res.ok) throw new ApiError(res.status, await res.text().catch(() => 'the code was not accepted'));
}
