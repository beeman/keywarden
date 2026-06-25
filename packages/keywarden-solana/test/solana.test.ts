import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'

import {
  deriveSolanaAddress,
  ensureUniqueSolanaAddresses,
  parseSolanaCliKeypairJson,
} from '../src'

function fixtureSecretKey(): Uint8Array {
  const seed = new Uint8Array(32).fill(1)
  const publicKey = ed25519.getPublicKey(seed)
  const secretKey = new Uint8Array(64)
  secretKey.set(seed)
  secretKey.set(publicKey, 32)
  return secretKey
}

describe('@keywarden/solana', () => {
  test('parses a Solana CLI keypair JSON array', () => {
    const secretKey = fixtureSecretKey()
    const parsed = parseSolanaCliKeypairJson({
      content: JSON.stringify(Array.from(secretKey)),
      filename: 'id.json',
      recordId: 'record',
    })

    expect(parsed.record.label).toBe('id')
    expect(parsed.record.publicAddress).toBe(deriveSolanaAddress(secretKey))
  })

  test('rejects structurally invalid keypair arrays', () => {
    expect(() =>
      parseSolanaCliKeypairJson({
        content: JSON.stringify([1, 2, 3]),
      }),
    ).toThrow('INVALID_KEYPAIR_FILE')
  })

  test('rejects duplicate addresses in a batch', () => {
    const secretKey = fixtureSecretKey()
    const first = parseSolanaCliKeypairJson({
      content: JSON.stringify(Array.from(secretKey)),
      recordId: 'first',
    }).record
    const second = {
      ...first,
      id: 'second',
    }

    expect(() => ensureUniqueSolanaAddresses([first, second])).toThrow(
      'DUPLICATE_ADDRESS',
    )
  })
})
