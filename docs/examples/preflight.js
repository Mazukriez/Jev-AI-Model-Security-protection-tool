import { scan } from '../../src/index.js';

export async function guardedDecision({ state, question, runJev }) {
  const preflight = scan({ state, question });
  if (preflight.decision !== 'ALLOW') {
    return { status: 'not_sent_to_provider', preflight };
  }
  const decision = await runJev({ state, question });
  return { status: 'completed', preflight, decision };
}
