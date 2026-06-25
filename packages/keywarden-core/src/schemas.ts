import { z } from 'zod'

import {
  MAX_IMPORT_FILES,
  MAX_PAIRING_RELAYS,
  MAX_TRANSFER_BUNDLE_BYTES,
} from './constants'

const base64UrlRegex = /^[\w-]+$/u
const lowercaseHex64Regex = /^[\da-f]{64}$/u

export const Base64UrlSchema = z.string().regex(base64UrlRegex)

export const IsoDateStringSchema = z.string().datetime({ offset: true })

export const NostrPubkeySchema = z.string().regex(lowercaseHex64Regex)

export const SolanaAddressSchema = z.string().min(32).max(44)

export const SecretRecordV1Schema = z
  .object({
    chain: z.literal('solana'),
    createdAt: IsoDateStringSchema,
    id: z.string().min(1),
    importedAt: IsoDateStringSchema,
    kind: z.literal('solana-keypair'),
    label: z.string().trim().min(1).max(128),
    origin: z
      .object({
        filename: z.string().max(255).optional(),
        type: z.literal('solana-cli-json'),
      })
      .strict(),
    payload: z
      .object({
        encoding: z.literal('base64url'),
        secretKey: Base64UrlSchema,
      })
      .strict(),
    publicAddress: SolanaAddressSchema,
    schema: z.literal('keywarden.secret-record'),
    version: z.literal(1),
  })
  .strict()

export const TransferBundleV1Schema = z
  .object({
    createdAt: IsoDateStringSchema,
    records: z.array(SecretRecordV1Schema).max(MAX_IMPORT_FILES),
    schema: z.literal('keywarden.transfer-bundle'),
    transferId: z.string().min(1),
    version: z.literal(1),
  })
  .strict()

export const TransferManifestV1Schema = z
  .object({
    bundleByteLength: z
      .number()
      .int()
      .nonnegative()
      .max(MAX_TRANSFER_BUNDLE_BYTES),
    bundleSha256: Base64UrlSchema,
    chunkCount: z.number().int().positive(),
    chunkPlaintextSize: z
      .number()
      .int()
      .positive()
      .max(16 * 1024),
    createdAt: IsoDateStringSchema,
    expiresAt: IsoDateStringSchema,
    recordCount: z.number().int().nonnegative().max(MAX_IMPORT_FILES),
    schema: z.literal('keywarden.transfer-manifest'),
    transferId: z.string().min(1),
    version: z.literal(1),
  })
  .strict()

export const TransferChunkV1Schema = z
  .object({
    bytes: Base64UrlSchema,
    chunkCount: z.number().int().positive(),
    chunkIndex: z.number().int().nonnegative(),
    schema: z.literal('keywarden.transfer-chunk'),
    transferId: z.string().min(1),
    version: z.literal(1),
  })
  .strict()

export const TransferAckV1Schema = z
  .object({
    bundleSha256: Base64UrlSchema,
    committedAt: IsoDateStringSchema,
    importedCount: z.number().int().nonnegative(),
    schema: z.literal('keywarden.transfer-ack'),
    skippedCount: z.number().int().nonnegative(),
    status: z.literal('committed'),
    transferId: z.string().min(1),
    version: z.literal(1),
  })
  .strict()

export const TransferErrorCodeSchema = z.enum([
  'DIGEST_MISMATCH',
  'INVALID_BUNDLE',
  'INVALID_MANIFEST',
  'INVALID_RECORD',
  'LIMIT_EXCEEDED',
  'MISSING_CHUNKS',
  'SESSION_EXPIRED',
  'STORAGE_FAILURE',
  'USER_REJECTED',
  'VAULT_LOCKED',
])

export const KeywardenMessageTypeSchema = z.enum([
  'pairing.cancel',
  'pairing.confirmed',
  'pairing.ready',
  'pairing.request',
  'transfer.ack',
  'transfer.chunk',
  'transfer.error',
  'transfer.manifest',
])

export const KeywardenMessageHeaderV1Schema = z
  .object({
    createdAt: IsoDateStringSchema,
    expiresAt: IsoDateStringSchema,
    messageId: z.string().min(1),
    pairingId: z.string().min(1),
    protocol: z.literal('keywarden'),
    recipientNostrPubkey: NostrPubkeySchema,
    senderNostrPubkey: NostrPubkeySchema,
    sequence: z.number().int().nonnegative(),
    type: KeywardenMessageTypeSchema,
    version: z.literal(1),
  })
  .strict()

export const PairingRequestBodyV1Schema = z
  .object({
    device: z
      .object({
        appVersion: z.string().min(1).max(64),
        deviceId: z.string().min(1).max(128),
        displayName: z.string().min(1).max(128),
        platform: z.literal('android'),
      })
      .strict(),
    header: KeywardenMessageHeaderV1Schema,
  })
  .strict()

export const PairingReadyBodyV1Schema = z
  .object({
    header: KeywardenMessageHeaderV1Schema,
  })
  .strict()

export const PairingConfirmedBodyV1Schema = z
  .object({
    header: KeywardenMessageHeaderV1Schema,
  })
  .strict()

export const PairingCancelBodyV1Schema = z
  .object({
    header: KeywardenMessageHeaderV1Schema,
    reason: z.enum([
      'code-mismatch',
      'expired',
      'protocol-error',
      'unsupported-version',
      'user-cancelled',
    ]),
  })
  .strict()

export const TransferManifestBodyV1Schema = z
  .object({
    header: KeywardenMessageHeaderV1Schema,
    manifest: TransferManifestV1Schema,
  })
  .strict()

export const TransferChunkBodyV1Schema = z
  .object({
    chunk: TransferChunkV1Schema,
    header: KeywardenMessageHeaderV1Schema,
  })
  .strict()

export const TransferAckBodyV1Schema = z
  .object({
    ack: TransferAckV1Schema,
    header: KeywardenMessageHeaderV1Schema,
  })
  .strict()

export const TransferErrorBodyV1Schema = z
  .object({
    code: TransferErrorCodeSchema,
    header: KeywardenMessageHeaderV1Schema,
  })
  .strict()

export const KeywardenMessageBodyV1Schema = z.union([
  PairingRequestBodyV1Schema,
  PairingReadyBodyV1Schema,
  PairingConfirmedBodyV1Schema,
  PairingCancelBodyV1Schema,
  TransferManifestBodyV1Schema,
  TransferChunkBodyV1Schema,
  TransferAckBodyV1Schema,
  TransferErrorBodyV1Schema,
])

export const EncryptedEnvelopeV1Schema = z
  .object({
    ciphertext: Base64UrlSchema,
    messageId: z.string().min(1),
    nonce: Base64UrlSchema,
    senderEcdhPublicKey: Base64UrlSchema.optional(),
    sequence: z.number().int().nonnegative(),
    version: z.literal(1),
  })
  .strict()

export const PairingQrV1Schema = z
  .object({
    expiresAt: z.number().int().positive(),
    mode: z.literal('web-to-mobile-import'),
    pairingId: Base64UrlSchema,
    pairingSecret: Base64UrlSchema,
    protocol: z.literal('keywarden'),
    relays: z.array(z.string().url()).min(1).max(MAX_PAIRING_RELAYS),
    version: z.literal(1),
    webEcdhPublicKey: Base64UrlSchema,
    webNostrPubkey: NostrPubkeySchema,
  })
  .strict()
