import type {
  SecretRecordV1,
  TransferAckV1,
  TransferBundleV1,
} from '@keywarden/core'
import {
  base64UrlToBytes,
  bytesToBase64Url,
  TransferBundleV1Schema,
} from '@keywarden/core'
import {
  decryptSecretRecord,
  encryptSecretRecord,
  type KeywardenCrypto,
} from '@keywarden/crypto'
import {
  ensureUniqueSolanaAddresses,
  revalidateSecretRecord,
} from '@keywarden/solana'

import type {
  EncryptedSecretRepository,
  EncryptedSecretRow,
  TransferReceiptRow,
} from './types'

export type VaultSession = {
  vaultId: string
  vaultKey: CryptoKey
}

export type ImportTransferInput = {
  bundle: TransferBundleV1
  bundleSha256: string
  cryptoAdapter: KeywardenCrypto
  pairingId: string
  repository: EncryptedSecretRepository
  senderNostrPubkey: string
  session: VaultSession
}

export type ImportTransferResult = {
  ack: TransferAckV1
  importedRecords: SecretRecordV1[]
  skippedCount: number
}

export async function createVaultSession(input: {
  cryptoAdapter: KeywardenCrypto
  vaultId?: string
  vaultKeyBytes?: Uint8Array
}): Promise<{
  session: VaultSession
  vaultKeyBytes: Uint8Array
}> {
  const vaultId =
    input.vaultId ?? bytesToBase64Url(input.cryptoAdapter.randomBytes(16))
  const vaultKeyBytes =
    input.vaultKeyBytes ?? input.cryptoAdapter.randomBytes(32)
  const vaultKey =
    await input.cryptoAdapter.importVaultEncryptionKey(vaultKeyBytes)

  return {
    session: {
      vaultId,
      vaultKey,
    },
    vaultKeyBytes,
  }
}

export async function decryptVaultRows(input: {
  cryptoAdapter: KeywardenCrypto
  rows: readonly EncryptedSecretRow[]
  session: VaultSession
}): Promise<SecretRecordV1[]> {
  return Promise.all(
    input.rows.map((row) =>
      decryptSecretRecord({
        cryptoAdapter: input.cryptoAdapter,
        encrypted: {
          ciphertext: row.ciphertext,
          nonce: row.nonce,
        },
        recordId: row.id,
        vaultId: input.session.vaultId,
        vaultKey: input.session.vaultKey,
      }),
    ),
  )
}

export async function importTransferBundle(
  input: ImportTransferInput,
): Promise<ImportTransferResult> {
  const bundle = TransferBundleV1Schema.parse(input.bundle)
  for (const record of bundle.records) {
    revalidateSecretRecord(record)
  }
  ensureUniqueSolanaAddresses(bundle.records)

  const importedRecords: SecretRecordV1[] = []
  const now = Date.now()
  let skippedCount = 0

  const ack = await input.repository.runImportTransaction(
    async (transaction) => {
      const existingAddresses = await transaction.findExistingPublicAddresses(
        input.session.vaultId,
        bundle.records.map((record) => record.publicAddress),
        (row) =>
          decryptSecretRecord({
            cryptoAdapter: input.cryptoAdapter,
            encrypted: {
              ciphertext: row.ciphertext,
              nonce: row.nonce,
            },
            recordId: row.id,
            vaultId: input.session.vaultId,
            vaultKey: input.session.vaultKey,
          }),
      )

      for (const record of bundle.records) {
        if (existingAddresses.has(record.publicAddress)) {
          skippedCount += 1
          continue
        }

        const encrypted = await encryptSecretRecord({
          cryptoAdapter: input.cryptoAdapter,
          record,
          vaultId: input.session.vaultId,
          vaultKey: input.session.vaultKey,
        })

        await transaction.insertSecret({
          cipherVersion: 1,
          ciphertext: encrypted.ciphertext,
          createdAt: now,
          id: record.id,
          nonce: encrypted.nonce,
          updatedAt: now,
          vaultId: input.session.vaultId,
        })
        importedRecords.push(record)
      }

      const receipt: TransferReceiptRow = {
        bundleSha256: input.bundleSha256,
        committedAt: now,
        id: crypto.randomUUID(),
        importedCount: importedRecords.length,
        pairingIdHash: bytesToBase64Url(
          await input.cryptoAdapter.sha256(
            new TextEncoder().encode(input.pairingId),
          ),
        ),
        senderNostrPubkeyHash: bytesToBase64Url(
          await input.cryptoAdapter.sha256(
            new TextEncoder().encode(input.senderNostrPubkey),
          ),
        ),
        skippedCount,
        transferIdHash: bytesToBase64Url(
          await input.cryptoAdapter.sha256(
            new TextEncoder().encode(bundle.transferId),
          ),
        ),
        vaultId: input.session.vaultId,
      }

      await transaction.insertTransferReceipt(receipt)

      return {
        bundleSha256: input.bundleSha256,
        committedAt: new Date(now).toISOString(),
        importedCount: importedRecords.length,
        schema: 'keywarden.transfer-ack',
        skippedCount,
        status: 'committed',
        transferId: bundle.transferId,
        version: 1,
      } satisfies TransferAckV1
    },
  )

  return {
    ack,
    importedRecords,
    skippedCount,
  }
}

export function decodeVaultKey(value: string): Uint8Array {
  const bytes = base64UrlToBytes(value)
  if (bytes.byteLength !== 32) {
    throw new Error('VAULT_UNAVAILABLE')
  }
  return bytes
}
