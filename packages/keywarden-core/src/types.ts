import type { z } from 'zod'

import type {
  EncryptedEnvelopeV1Schema,
  KeywardenMessageBodyV1Schema,
  KeywardenMessageHeaderV1Schema,
  KeywardenMessageTypeSchema,
  PairingQrV1Schema,
  SecretRecordV1Schema,
  TransferAckV1Schema,
  TransferBundleV1Schema,
  TransferChunkV1Schema,
  TransferErrorCodeSchema,
  TransferManifestV1Schema,
} from './schemas'

export type EncryptedEnvelopeV1 = z.infer<typeof EncryptedEnvelopeV1Schema>

export type KeywardenAadV1 = {
  protocol: 'keywarden'
  version: 1
  pairingId: string
  messageId: string
  sequence: number
  senderNostrPubkey: string
  recipientNostrPubkey: string
  senderEcdhPublicKey?: string
}

export type KeywardenMessageBodyV1 = z.infer<
  typeof KeywardenMessageBodyV1Schema
>

export type KeywardenMessageHeaderV1 = z.infer<
  typeof KeywardenMessageHeaderV1Schema
>

export type KeywardenMessageType = z.infer<typeof KeywardenMessageTypeSchema>

export type PairingKeyInfoV1 = {
  protocol: 'keywarden'
  version: 1
  purpose: 'pairing-key-material'
  pairingId: string
  webNostrPubkey: string
  mobileNostrPubkey: string
  webEcdhPublicKey: string
  mobileEcdhPublicKey: string
}

export type PairingQrV1 = z.infer<typeof PairingQrV1Schema>

export type SecretRecordV1 = z.infer<typeof SecretRecordV1Schema>

export type TransferAckV1 = z.infer<typeof TransferAckV1Schema>

export type TransferBundleV1 = z.infer<typeof TransferBundleV1Schema>

export type TransferChunkV1 = z.infer<typeof TransferChunkV1Schema>

export type TransferErrorCode = z.infer<typeof TransferErrorCodeSchema>

export type TransferManifestV1 = z.infer<typeof TransferManifestV1Schema>
