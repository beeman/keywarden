export type WebImportState =
  | 'awaiting-ack'
  | 'awaiting-local-confirmation'
  | 'awaiting-mobile'
  | 'awaiting-peer-confirmation'
  | 'cancelled'
  | 'complete'
  | 'creating-session'
  | 'error'
  | 'expired'
  | 'idle'
  | 'parsing-files'
  | 'publishing'
  | 'ready-for-files'
  | 'review'

export type MobileImportState =
  | 'awaiting-local-confirmation'
  | 'awaiting-peer-confirmation'
  | 'cancelled'
  | 'committing'
  | 'complete'
  | 'connecting'
  | 'error'
  | 'expired'
  | 'import-review'
  | 'locked'
  | 'ready'
  | 'receiving-chunks'
  | 'scanning'
  | 'sending-ack'
  | 'unlocking'
  | 'validating'
  | 'waiting-for-manifest'

const terminalStates = new Set(['cancelled', 'complete', 'error', 'expired'])

export function canSelectFiles(state: WebImportState): boolean {
  return state === 'ready-for-files' || state === 'review'
}

export function isTerminalState(
  state: MobileImportState | WebImportState,
): boolean {
  return terminalStates.has(state)
}
