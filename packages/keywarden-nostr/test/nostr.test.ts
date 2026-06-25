import { describe, expect, test } from 'bun:test'
import { bytesToBase64Url } from '@keywarden/core'

import {
  createKeywardenEvent,
  createKeywardenNostrKeypair,
  DuplicateTracker,
  validateKeywardenEvent,
} from '../src'

describe('@keywarden/nostr', () => {
  test('signs and verifies Keywarden events', () => {
    const keypair = createKeywardenNostrKeypair()
    const pairingId = bytesToBase64Url(new Uint8Array(16).fill(1))
    const event = createKeywardenEvent({
      envelope: {
        ciphertext: bytesToBase64Url(new Uint8Array([1, 2, 3])),
        messageId: 'message',
        nonce: bytesToBase64Url(new Uint8Array(12).fill(2)),
        sequence: 0,
        version: 1,
      },
      expiresAtUnixSeconds: Math.floor(Date.now() / 1000) + 60,
      pairingId,
      recipientNostrPubkey: keypair.publicKey,
      secretKey: keypair.secretKey,
    })

    expect(() =>
      validateKeywardenEvent({
        event,
        expectedPairingId: pairingId,
        expectedRecipientNostrPubkey: keypair.publicKey,
      }),
    ).not.toThrow()
  })

  test('deduplicates by event and message id', () => {
    const keypair = createKeywardenNostrKeypair()
    const event = createKeywardenEvent({
      envelope: {
        ciphertext: bytesToBase64Url(new Uint8Array([1, 2, 3])),
        messageId: 'message',
        nonce: bytesToBase64Url(new Uint8Array(12).fill(2)),
        sequence: 0,
        version: 1,
      },
      expiresAtUnixSeconds: Math.floor(Date.now() / 1000) + 60,
      pairingId: 'pairing',
      recipientNostrPubkey: keypair.publicKey,
      secretKey: keypair.secretKey,
    })
    const tracker = new DuplicateTracker()

    expect(tracker.accept(event)).toBe(true)
    expect(tracker.accept(event)).toBe(false)
  })
})
