import type { SecretRecordV1 } from '@keywarden/core'

export type EncryptedSecretRow = {
  cipherVersion: 1
  ciphertext: string
  createdAt: number
  deletedAt?: number
  id: string
  nonce: string
  updatedAt: number
  vaultId: string
}

export type TransferReceiptRow = {
  bundleSha256: string
  committedAt: number
  id: string
  importedCount: number
  pairingIdHash: string
  senderNostrPubkeyHash: string
  skippedCount: number
  transferIdHash: string
  vaultId: string
}

export interface EncryptedSecretRepository {
  list(vaultId: string): Promise<EncryptedSecretRow[]>

  runImportTransaction<T>(
    operation: (transaction: EncryptedSecretTransaction) => Promise<T>,
  ): Promise<T>
}

export interface EncryptedSecretTransaction {
  findExistingPublicAddresses(
    vaultId: string,
    addresses: readonly string[],
    decryptRecord: (row: EncryptedSecretRow) => Promise<SecretRecordV1>,
  ): Promise<Set<string>>

  insertSecret(row: EncryptedSecretRow): Promise<void>

  insertTransferReceipt(receipt: TransferReceiptRow): Promise<void>
}
