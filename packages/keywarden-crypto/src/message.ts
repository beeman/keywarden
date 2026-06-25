import type {
  EncryptedEnvelopeV1,
  KeywardenMessageBodyV1,
} from '@keywarden/core'
import {
  base64UrlToBytes,
  buildAad,
  bytesToBase64Url,
  EncryptedEnvelopeV1Schema,
  parseKeywardenMessage,
  serializeKeywardenMessage,
} from '@keywarden/core'

import type { KeywardenCrypto } from './types'

export async function decryptProtocolMessage(input: {
  cryptoAdapter: KeywardenCrypto
  encryptionKey: CryptoKey
  envelope: EncryptedEnvelopeV1
  pairingId: string
  recipientNostrPubkey: string
  senderNostrPubkey: string
}): Promise<KeywardenMessageBodyV1> {
  const aad = buildAad({
    messageId: input.envelope.messageId,
    pairingId: input.pairingId,
    protocol: 'keywarden',
    recipientNostrPubkey: input.recipientNostrPubkey,
    senderEcdhPublicKey: input.envelope.senderEcdhPublicKey,
    senderNostrPubkey: input.senderNostrPubkey,
    sequence: input.envelope.sequence,
    version: 1,
  })
  const plaintext = await input.cryptoAdapter.decrypt({
    aad,
    ciphertext: base64UrlToBytes(input.envelope.ciphertext),
    key: input.encryptionKey,
    nonce: base64UrlToBytes(input.envelope.nonce),
  })
  const message = parseKeywardenMessage(plaintext)

  if (
    message.header.messageId !== input.envelope.messageId ||
    message.header.pairingId !== input.pairingId ||
    message.header.recipientNostrPubkey !== input.recipientNostrPubkey ||
    message.header.senderNostrPubkey !== input.senderNostrPubkey ||
    message.header.sequence !== input.envelope.sequence
  ) {
    throw new Error('PROTOCOL_VIOLATION')
  }

  return message
}

export async function encryptProtocolMessage(input: {
  body: KeywardenMessageBodyV1
  cryptoAdapter: KeywardenCrypto
  encryptionKey: CryptoKey
  senderEcdhPublicKey?: string
}): Promise<EncryptedEnvelopeV1> {
  const aad = buildAad({
    messageId: input.body.header.messageId,
    pairingId: input.body.header.pairingId,
    protocol: 'keywarden',
    recipientNostrPubkey: input.body.header.recipientNostrPubkey,
    senderEcdhPublicKey: input.senderEcdhPublicKey,
    senderNostrPubkey: input.body.header.senderNostrPubkey,
    sequence: input.body.header.sequence,
    version: 1,
  })
  const encrypted = await input.cryptoAdapter.encrypt({
    aad,
    key: input.encryptionKey,
    plaintext: serializeKeywardenMessage(input.body),
  })

  return EncryptedEnvelopeV1Schema.parse({
    ciphertext: bytesToBase64Url(encrypted.ciphertext),
    messageId: input.body.header.messageId,
    nonce: bytesToBase64Url(encrypted.nonce),
    senderEcdhPublicKey: input.senderEcdhPublicKey,
    sequence: input.body.header.sequence,
    version: 1,
  })
}

export async function deriveVerificationCode(
  cryptoAdapter: KeywardenCrypto,
  verificationKey: CryptoKey,
): Promise<string> {
  const bytes = await cryptoAdapter.hmacSha256(
    verificationKey,
    new TextEncoder().encode('keywarden/verification-code/v1'),
  )
  const value = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength,
  ).getUint32(0, false)

  return String(value % 1_000_000).padStart(6, '0')
}
