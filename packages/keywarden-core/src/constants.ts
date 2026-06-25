export const ACK_WAIT_SECONDS = 5 * 60

export const DEFAULT_CHUNK_PLAINTEXT_BYTES = 4096

export const DEFAULT_KEYWARDEN_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
] as const

export const KEYWARDEN_NOSTR_KIND = {
  MESSAGE: 3940,
  SIGNAL: 23940,
  STATE: 33940,
} as const

export const MAX_IMPORT_FILE_BYTES = 64 * 1024

export const MAX_IMPORT_FILES = 500

export const MAX_PAIRING_RELAYS = 5

export const MAX_TRANSFER_BUNDLE_BYTES = 1024 * 1024

export const PAIRING_TTL_SECONDS = 15 * 60

export const TRANSFER_EVENT_TTL_SECONDS = 60 * 60
