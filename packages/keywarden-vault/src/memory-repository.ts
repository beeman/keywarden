import type {
  EncryptedSecretRepository,
  EncryptedSecretRow,
  EncryptedSecretTransaction,
  TransferReceiptRow,
} from './types'

export class InMemoryEncryptedSecretRepository
  implements EncryptedSecretRepository
{
  private receipts: TransferReceiptRow[] = []
  private rows: EncryptedSecretRow[] = []

  async list(vaultId: string): Promise<EncryptedSecretRow[]> {
    return this.rows.filter((row) => row.vaultId === vaultId && !row.deletedAt)
  }

  async listReceipts(vaultId: string): Promise<TransferReceiptRow[]> {
    return this.receipts.filter((receipt) => receipt.vaultId === vaultId)
  }

  async runImportTransaction<T>(
    operation: (transaction: EncryptedSecretTransaction) => Promise<T>,
  ): Promise<T> {
    const nextRows = [...this.rows]
    const nextReceipts = [...this.receipts]
    const transaction = new InMemoryEncryptedSecretTransaction(
      nextRows,
      nextReceipts,
    )
    const result = await operation(transaction)
    this.rows = nextRows
    this.receipts = nextReceipts
    return result
  }
}

class InMemoryEncryptedSecretTransaction implements EncryptedSecretTransaction {
  constructor(
    private readonly rows: EncryptedSecretRow[],
    private readonly receipts: TransferReceiptRow[],
  ) {}

  async findExistingPublicAddresses(
    vaultId: string,
    addresses: readonly string[],
    decryptRecord: (
      row: EncryptedSecretRow,
    ) => Promise<{ publicAddress: string }>,
  ): Promise<Set<string>> {
    const wanted = new Set(addresses)
    const existing = new Set<string>()

    for (const row of this.rows) {
      if (row.vaultId !== vaultId || row.deletedAt) {
        continue
      }

      const record = await decryptRecord(row)
      if (wanted.has(record.publicAddress)) {
        existing.add(record.publicAddress)
      }
    }

    return existing
  }

  async insertSecret(row: EncryptedSecretRow): Promise<void> {
    if (this.rows.some((existing) => existing.id === row.id)) {
      throw new Error('STORAGE_FAILED')
    }
    this.rows.push(row)
  }

  async insertTransferReceipt(receipt: TransferReceiptRow): Promise<void> {
    if (
      this.receipts.some(
        (existing) =>
          existing.bundleSha256 === receipt.bundleSha256 &&
          existing.vaultId === receipt.vaultId,
      )
    ) {
      return
    }
    this.receipts.push(receipt)
  }
}
