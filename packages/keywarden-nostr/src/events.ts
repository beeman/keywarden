import type { EncryptedEnvelopeV1 } from '@keywarden/core'
import {
  EncryptedEnvelopeV1Schema,
  KEYWARDEN_NOSTR_KIND,
  parseEnvelope,
} from '@keywarden/core'
import type { Event, EventTemplate, Filter, VerifiedEvent } from 'nostr-tools'
import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  verifyEvent,
} from 'nostr-tools/pure'

export type KeywardenNostrKeypair = {
  publicKey: string
  secretKey: Uint8Array
}

export type KeywardenNostrEventInput = {
  envelope: EncryptedEnvelopeV1
  expiresAtUnixSeconds: number
  pairingId: string
  recipientNostrPubkey: string
  secretKey: Uint8Array
}

export type NostrEvent = Event

export type NostrFilter = Filter

export function createKeywardenNostrKeypair(): KeywardenNostrKeypair {
  const secretKey = generateSecretKey()
  return {
    publicKey: getPublicKey(secretKey),
    secretKey,
  }
}

export function createKeywardenEvent(
  input: KeywardenNostrEventInput,
): VerifiedEvent {
  const template: EventTemplate = {
    content: JSON.stringify(EncryptedEnvelopeV1Schema.parse(input.envelope)),
    created_at: Math.floor(Date.now() / 1000),
    kind: KEYWARDEN_NOSTR_KIND.MESSAGE,
    tags: [
      ['d', input.pairingId],
      ['expiration', String(input.expiresAtUnixSeconds)],
      ['p', input.recipientNostrPubkey],
      ['t', 'keywarden'],
      ['v', '1'],
    ],
  }

  return finalizeEvent(template, input.secretKey)
}

export function createKeywardenSubscriptionFilter(input: {
  pairingId: string
  receiverNostrPubkey: string
  sessionExpiresAtUnixSeconds: number
  sessionStartedAtUnixSeconds: number
}): Filter {
  return {
    '#d': [input.pairingId],
    '#p': [input.receiverNostrPubkey],
    '#t': ['keywarden'],
    kinds: [KEYWARDEN_NOSTR_KIND.MESSAGE],
    limit: 1000,
    since: input.sessionStartedAtUnixSeconds - 30,
    until: input.sessionExpiresAtUnixSeconds + 60,
  }
}

export function getTagValue(event: Event, tagName: string): string | undefined {
  return event.tags.find((tag) => tag[0] === tagName)?.[1]
}

export function parseKeywardenEventEnvelope(event: Event): EncryptedEnvelopeV1 {
  return parseEnvelope(event.content)
}

export function validateKeywardenEvent(input: {
  event: Event
  expectedPairingId: string
  expectedRecipientNostrPubkey: string
  maxCreatedAtUnixSeconds?: number
  minCreatedAtUnixSeconds?: number
  nowUnixSeconds?: number
}): VerifiedEvent {
  const nowUnixSeconds = input.nowUnixSeconds ?? Math.floor(Date.now() / 1000)

  if (!verifyEvent(input.event)) {
    throw new Error('INVALID_NOSTR_EVENT')
  }
  if (input.event.kind !== KEYWARDEN_NOSTR_KIND.MESSAGE) {
    throw new Error('INVALID_NOSTR_EVENT')
  }
  if (getTagValue(input.event, 't') !== 'keywarden') {
    throw new Error('INVALID_NOSTR_EVENT')
  }
  if (getTagValue(input.event, 'v') !== '1') {
    throw new Error('INVALID_NOSTR_EVENT')
  }
  if (getTagValue(input.event, 'd') !== input.expectedPairingId) {
    throw new Error('INVALID_NOSTR_EVENT')
  }
  if (getTagValue(input.event, 'p') !== input.expectedRecipientNostrPubkey) {
    throw new Error('INVALID_NOSTR_EVENT')
  }

  const expiration = Number(getTagValue(input.event, 'expiration'))
  if (!Number.isInteger(expiration) || expiration <= nowUnixSeconds) {
    throw new Error('SESSION_EXPIRED')
  }
  if (
    input.minCreatedAtUnixSeconds !== undefined &&
    input.event.created_at < input.minCreatedAtUnixSeconds
  ) {
    throw new Error('INVALID_NOSTR_EVENT')
  }
  if (
    input.maxCreatedAtUnixSeconds !== undefined &&
    input.event.created_at > input.maxCreatedAtUnixSeconds
  ) {
    throw new Error('INVALID_NOSTR_EVENT')
  }

  parseKeywardenEventEnvelope(input.event)

  return input.event as VerifiedEvent
}

export class DuplicateTracker {
  readonly eventIds = new Set<string>()
  readonly messageIds = new Set<string>()

  accept(event: Event): boolean {
    if (this.eventIds.has(event.id)) {
      return false
    }

    const envelope = parseKeywardenEventEnvelope(event)
    if (this.messageIds.has(envelope.messageId)) {
      return false
    }

    this.eventIds.add(event.id)
    this.messageIds.add(envelope.messageId)
    return true
  }
}
