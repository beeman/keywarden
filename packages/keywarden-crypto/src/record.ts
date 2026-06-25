import type { SecretRecordV1 } from '@keywarden/core'
import {
  base64UrlToBytes,
  bytesToBase64Url,
  stableUtf8Json,
} from '@keywarden/core'

import type { KeywardenCrypto } from './types'

export type EncryptedRecordPayload = {
  ciphertext: string
  nonce: string
}

export async function deriveRecordKey(input: {
  cryptoAdapter: KeywardenCrypto
  recordId: string
  vaultKey: CryptoKey
}): Promise<CryptoKey> {
  return input.cryptoAdapter.deriveRecordKey({
    recordId: input.recordId,
    vaultKey: input.vaultKey,
  })
}

export async function decryptSecretRecord(input: {
  cryptoAdapter: KeywardenCrypto
  encrypted: EncryptedRecordPayload
  recordId: string
  vaultId: string
  vaultKey: CryptoKey
}): Promise<SecretRecordV1> {
  const recordKey = await deriveRecordKey({
    cryptoAdapter: input.cryptoAdapter,
    recordId: input.recordId,
    vaultKey: input.vaultKey,
  })
  const plaintext = await input.cryptoAdapter.decrypt({
    aad: stableUtf8Json({
      protocol: 'keywarden',
      recordId: input.recordId,
      recordSchema: 'secret-record-v1',
      vaultId: input.vaultId,
      version: 1,
    }),
    ciphertext: base64UrlToBytes(input.encrypted.ciphertext),
    key: recordKey,
    nonce: base64UrlToBytes(input.encrypted.nonce),
  })

  return JSON.parse(new TextDecoder().decode(plaintext)) as SecretRecordV1
}

export async function encryptSecretRecord(input: {
  cryptoAdapter: KeywardenCrypto
  record: SecretRecordV1
  vaultId: string
  vaultKey: CryptoKey
}): Promise<EncryptedRecordPayload> {
  const recordKey = await deriveRecordKey({
    cryptoAdapter: input.cryptoAdapter,
    recordId: input.record.id,
    vaultKey: input.vaultKey,
  })
  const encrypted = await input.cryptoAdapter.encrypt({
    aad: stableUtf8Json({
      protocol: 'keywarden',
      recordId: input.record.id,
      recordSchema: 'secret-record-v1',
      vaultId: input.vaultId,
      version: 1,
    }),
    key: recordKey,
    plaintext: new TextEncoder().encode(JSON.stringify(input.record)),
  })

  return {
    ciphertext: bytesToBase64Url(encrypted.ciphertext),
    nonce: bytesToBase64Url(encrypted.nonce),
  }
}
