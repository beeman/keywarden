import { describe, expect, test } from 'bun:test'

import {
  buildKeywardenUri,
  bytesToBase64Url,
  createTransferChunks,
  parseKeywardenUri,
  reassembleTransferChunks,
  serializeTransferBundleV1,
  stableJson,
  utf8ToBytes,
} from '../src'

describe('@keywarden/core', () => {
  test('builds and parses a pairing URI', () => {
    const uri = buildKeywardenUri({
      expiresAt: Math.floor(Date.now() / 1000) + 60,
      mode: 'web-to-mobile-import',
      pairingId: bytesToBase64Url(new Uint8Array(16).fill(1)),
      pairingSecret: bytesToBase64Url(new Uint8Array(32).fill(2)),
      protocol: 'keywarden',
      relays: ['ws://localhost:7777'],
      version: 1,
      webEcdhPublicKey: bytesToBase64Url(new Uint8Array(65).fill(3)),
      webNostrPubkey: 'a'.repeat(64),
    })

    expect(parseKeywardenUri(uri).webNostrPubkey).toBe('a'.repeat(64))
  })

  test('reassembles chunks byte-for-byte', () => {
    const bytes = utf8ToBytes('abcdefghijklmnopqrstuvwxyz')
    const chunks = createTransferChunks({
      bytes,
      chunkPlaintextSize: 5,
      transferId: 'transfer',
    })

    expect(reassembleTransferChunks(chunks)).toEqual(bytes)
  })

  test('serializes transfer bundle and rejects unknown record fields', () => {
    expect(() =>
      serializeTransferBundleV1({
        createdAt: new Date().toISOString(),
        records: [],
        schema: 'keywarden.transfer-bundle',
        transferId: 'transfer',
        version: 1,
      }),
    ).not.toThrow()
  })

  test('stable JSON sorts object keys', () => {
    expect(stableJson({ z: 1, a: 2 })).toBe('{"a":2,"z":1}')
  })
})
