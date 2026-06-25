import { describe, expect, test } from 'bun:test'
import { bytesToBase64Url } from '@keywarden/core'
import { createWebCryptoAdapter } from '@keywarden/crypto'
import { parseSolanaCliKeypairJson } from '@keywarden/solana'
import { ed25519 } from '@noble/curves/ed25519.js'

import {
  createVaultSession,
  decryptVaultRows,
  InMemoryEncryptedSecretRepository,
  importTransferBundle,
} from '../src'

function fixtureRecord() {
  const seed = new Uint8Array(32).fill(3)
  const publicKey = ed25519.getPublicKey(seed)
  const secretKey = new Uint8Array(64)
  secretKey.set(seed)
  secretKey.set(publicKey, 32)
  return parseSolanaCliKeypairJson({
    content: JSON.stringify(Array.from(secretKey)),
    recordId: 'record',
  }).record
}

describe('@keywarden/vault', () => {
  test('encrypts imported records and skips duplicates on retry', async () => {
    const cryptoAdapter = createWebCryptoAdapter(globalThis.crypto)
    const repository = new InMemoryEncryptedSecretRepository()
    const { session } = await createVaultSession({
      cryptoAdapter,
      vaultKeyBytes: new Uint8Array(32).fill(9),
      vaultId: 'vault',
    })
    const record = fixtureRecord()
    const bundle = {
      createdAt: new Date().toISOString(),
      records: [record],
      schema: 'keywarden.transfer-bundle' as const,
      transferId: 'transfer',
      version: 1 as const,
    }
    const first = await importTransferBundle({
      bundle,
      bundleSha256: bytesToBase64Url(new Uint8Array(32).fill(1)),
      cryptoAdapter,
      pairingId: 'pairing',
      repository,
      senderNostrPubkey: 'a'.repeat(64),
      session,
    })

    expect(first.ack.importedCount).toBe(1)
    expect(first.ack.skippedCount).toBe(0)

    const rows = await repository.list('vault')
    expect(rows[0]?.ciphertext).not.toContain(record.publicAddress)

    const decrypted = await decryptVaultRows({
      cryptoAdapter,
      rows,
      session,
    })
    expect(decrypted[0]?.publicAddress).toBe(record.publicAddress)
  })
})
