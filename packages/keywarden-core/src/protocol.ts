import {
  DEFAULT_CHUNK_PLAINTEXT_BYTES,
  TRANSFER_EVENT_TTL_SECONDS,
} from './constants'
import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToUtf8,
  concatBytes,
  utf8ToBytes,
} from './encoding'
import { stringifyAad } from './json'
import {
  EncryptedEnvelopeV1Schema,
  KeywardenMessageBodyV1Schema,
  PairingQrV1Schema,
  TransferBundleV1Schema,
} from './schemas'
import type {
  EncryptedEnvelopeV1,
  KeywardenAadV1,
  KeywardenMessageBodyV1,
  KeywardenMessageHeaderV1,
  KeywardenMessageType,
  PairingQrV1,
  TransferBundleV1,
  TransferChunkV1,
  TransferManifestV1,
} from './types'

export function buildAad(input: KeywardenAadV1): Uint8Array {
  return utf8ToBytes(stringifyAad(input))
}

export function buildKeywardenUri(payload: PairingQrV1): string {
  const parsed = PairingQrV1Schema.parse(payload)
  return `keywarden:/v1/pair?data=${bytesToBase64Url(utf8ToBytes(JSON.stringify(parsed)))}`
}

export function createMessageHeader(input: {
  expiresAt?: Date
  messageId?: string
  pairingId: string
  recipientNostrPubkey: string
  senderNostrPubkey: string
  sequence: number
  type: KeywardenMessageType
}): KeywardenMessageHeaderV1 {
  const createdAt = new Date()
  const expiresAt =
    input.expiresAt ??
    new Date(createdAt.getTime() + TRANSFER_EVENT_TTL_SECONDS * 1000)

  return {
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    messageId: input.messageId ?? crypto.randomUUID(),
    pairingId: input.pairingId,
    protocol: 'keywarden',
    recipientNostrPubkey: input.recipientNostrPubkey,
    senderNostrPubkey: input.senderNostrPubkey,
    sequence: input.sequence,
    type: input.type,
    version: 1,
  }
}

export function parseEnvelope(value: string): EncryptedEnvelopeV1 {
  return EncryptedEnvelopeV1Schema.parse(JSON.parse(value))
}

export function parseKeywardenMessage(
  bytes: Uint8Array,
): KeywardenMessageBodyV1 {
  return KeywardenMessageBodyV1Schema.parse(JSON.parse(bytesToUtf8(bytes)))
}

export function parseKeywardenUri(
  input: string,
  now = Math.floor(Date.now() / 1000),
): PairingQrV1 {
  if (input.length > 4096) {
    throw new Error('QR payload is too large')
  }

  const url = new URL(input)
  if (url.protocol !== 'keywarden:' || url.pathname !== '/v1/pair') {
    throw new Error('Invalid Keywarden URI')
  }

  const data = url.searchParams.get('data')
  if (!data) {
    throw new Error('Missing Keywarden URI data')
  }

  const parsed = PairingQrV1Schema.parse(
    JSON.parse(bytesToUtf8(base64UrlToBytes(data))),
  )

  if (parsed.expiresAt <= now) {
    throw new Error('Pairing QR has expired')
  }

  const seenRelays = new Set<string>()
  for (const relay of parsed.relays) {
    const relayUrl = new URL(relay)
    const isLocal =
      relayUrl.hostname === 'localhost' ||
      relayUrl.hostname === '127.0.0.1' ||
      relayUrl.hostname === '[::1]' ||
      relayUrl.hostname === '::1'

    if (relayUrl.username || relayUrl.password || relayUrl.hash) {
      throw new Error('Relay URL must not include credentials or fragments')
    }
    if (
      relayUrl.protocol !== 'wss:' &&
      !(isLocal && relayUrl.protocol === 'ws:')
    ) {
      throw new Error('Relay URL must use wss except for local development')
    }
    if (seenRelays.has(relay)) {
      throw new Error('Duplicate relay URL')
    }
    seenRelays.add(relay)
  }

  return parsed
}

export function serializeKeywardenMessage(
  body: KeywardenMessageBodyV1,
): Uint8Array {
  return utf8ToBytes(JSON.stringify(KeywardenMessageBodyV1Schema.parse(body)))
}

export function serializeTransferBundleV1(
  bundle: TransferBundleV1,
): Uint8Array {
  return utf8ToBytes(JSON.stringify(TransferBundleV1Schema.parse(bundle)))
}

export function createTransferChunks(input: {
  bytes: Uint8Array
  chunkPlaintextSize?: number
  transferId: string
}): TransferChunkV1[] {
  const chunkPlaintextSize =
    input.chunkPlaintextSize ?? DEFAULT_CHUNK_PLAINTEXT_BYTES
  const chunkCount = Math.max(
    1,
    Math.ceil(input.bytes.byteLength / chunkPlaintextSize),
  )

  return Array.from({ length: chunkCount }, (_, chunkIndex) => {
    const start = chunkIndex * chunkPlaintextSize
    const bytes = input.bytes.subarray(start, start + chunkPlaintextSize)

    return {
      bytes: bytesToBase64Url(bytes),
      chunkCount,
      chunkIndex,
      schema: 'keywarden.transfer-chunk',
      transferId: input.transferId,
      version: 1,
    }
  })
}

export function createTransferManifest(input: {
  bundleByteLength: number
  bundleSha256: string
  chunkCount: number
  chunkPlaintextSize?: number
  createdAt?: Date
  expiresAt?: Date
  recordCount: number
  transferId: string
}): TransferManifestV1 {
  const createdAt = input.createdAt ?? new Date()
  const expiresAt =
    input.expiresAt ??
    new Date(createdAt.getTime() + TRANSFER_EVENT_TTL_SECONDS * 1000)

  return {
    bundleByteLength: input.bundleByteLength,
    bundleSha256: input.bundleSha256,
    chunkCount: input.chunkCount,
    chunkPlaintextSize:
      input.chunkPlaintextSize ?? DEFAULT_CHUNK_PLAINTEXT_BYTES,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    recordCount: input.recordCount,
    schema: 'keywarden.transfer-manifest',
    transferId: input.transferId,
    version: 1,
  }
}

export function reassembleTransferChunks(
  chunks: readonly TransferChunkV1[],
): Uint8Array {
  if (chunks.length === 0) {
    throw new Error('Missing transfer chunks')
  }

  const first = chunks[0]
  if (!first) {
    throw new Error('Missing transfer chunks')
  }

  const expectedCount = first.chunkCount
  const byIndex = new Map<number, TransferChunkV1>()

  for (const chunk of chunks) {
    if (
      chunk.chunkCount !== expectedCount ||
      chunk.transferId !== first.transferId ||
      chunk.chunkIndex >= expectedCount
    ) {
      throw new Error('Invalid transfer chunk set')
    }

    byIndex.set(chunk.chunkIndex, chunk)
  }

  if (byIndex.size !== expectedCount) {
    throw new Error('Missing transfer chunks')
  }

  return concatBytes(
    Array.from({ length: expectedCount }, (_, index) => {
      const chunk = byIndex.get(index)
      if (!chunk) {
        throw new Error('Missing transfer chunk')
      }
      return base64UrlToBytes(chunk.bytes)
    }),
  )
}
