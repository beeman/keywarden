import type { SecretRecordV1 } from '@keywarden/core'
import {
  base64UrlToBytes,
  bytesToBase64Url,
  MAX_IMPORT_FILE_BYTES,
} from '@keywarden/core'
import { ed25519 } from '@noble/curves/ed25519.js'
import bs58 from 'bs58'

export type ParsedSolanaKeypairFile = {
  filename?: string
  record: SecretRecordV1
  secretKey: Uint8Array
}

export function deriveSolanaAddress(secretKey: Uint8Array): string {
  return bs58.encode(deriveSolanaPublicKey(secretKey))
}

export function deriveSolanaPublicKey(secretKey: Uint8Array): Uint8Array {
  if (secretKey.byteLength !== 64) {
    throw new Error('INVALID_KEYPAIR_FILE')
  }

  const seed = secretKey.slice(0, 32)
  const publicKey = ed25519.getPublicKey(seed)
  const embeddedPublicKey = secretKey.slice(32)

  if (!constantTimeEqual(publicKey, embeddedPublicKey)) {
    throw new Error('INVALID_KEYPAIR_FILE')
  }

  return publicKey
}

export function ensureUniqueSolanaAddresses(
  records: readonly SecretRecordV1[],
): void {
  const seen = new Set<string>()

  for (const record of records) {
    if (seen.has(record.publicAddress)) {
      throw new Error('DUPLICATE_ADDRESS')
    }
    seen.add(record.publicAddress)
  }
}

export function parseSolanaCliKeypairJson(input: {
  content: string
  filename?: string
  importedAt?: Date
  recordId?: string
}): ParsedSolanaKeypairFile {
  const byteLength = new TextEncoder().encode(input.content).byteLength
  if (byteLength > MAX_IMPORT_FILE_BYTES) {
    throw new Error('FILE_TOO_LARGE')
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(input.content)
  } catch {
    throw new Error('INVALID_KEYPAIR_FILE')
  }

  if (!Array.isArray(parsed) || parsed.length !== 64) {
    throw new Error('INVALID_KEYPAIR_FILE')
  }

  const secretKey = new Uint8Array(64)
  for (const [index, value] of parsed.entries()) {
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      throw new Error('INVALID_KEYPAIR_FILE')
    }
    secretKey[index] = value
  }

  const publicAddress = deriveSolanaAddress(secretKey)
  const importedAt = input.importedAt ?? new Date()
  const filename = input.filename?.slice(0, 255)
  const label = labelFromFilename(filename)
  const record: SecretRecordV1 = {
    chain: 'solana',
    createdAt: importedAt.toISOString(),
    id: input.recordId ?? crypto.randomUUID(),
    importedAt: importedAt.toISOString(),
    kind: 'solana-keypair',
    label,
    origin: {
      filename,
      type: 'solana-cli-json',
    },
    payload: {
      encoding: 'base64url',
      secretKey: bytesToBase64Url(secretKey),
    },
    publicAddress,
    schema: 'keywarden.secret-record',
    version: 1,
  }

  return {
    filename,
    record,
    secretKey,
  }
}

export function revalidateSecretRecord(record: SecretRecordV1): void {
  const secretKey = base64UrlToBytes(record.payload.secretKey)
  if (secretKey.byteLength !== 64) {
    throw new Error('INVALID_RECORD')
  }
  if (deriveSolanaAddress(secretKey) !== record.publicAddress) {
    throw new Error('INVALID_RECORD')
  }
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false
  }

  let diff = 0
  for (let index = 0; index < left.byteLength; index++) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0)
  }
  return diff === 0
}

function labelFromFilename(filename: string | undefined): string {
  if (!filename) {
    return 'Solana keypair'
  }

  const normalized = filename
    .trim()
    .replace(/\.[^.]+$/u, '')
    .trim()
  return (normalized || 'Solana keypair').slice(0, 128)
}
