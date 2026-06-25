import type { SecretRecordV1 } from '@keywarden/core'
import type {
  EncryptedSecretRepository,
  EncryptedSecretRow,
  EncryptedSecretTransaction,
  TransferReceiptRow,
} from '@keywarden/vault'
import * as SecureStore from 'expo-secure-store'
import { openDatabaseSync, type SQLiteDatabase } from 'expo-sqlite'

type EncryptedSecretSqlRow = {
  cipher_version: 1
  ciphertext: string
  created_at: number
  deleted_at: number | null
  id: string
  nonce: string
  updated_at: number
  vault_id: string
}

export class ExpoSqliteEncryptedSecretRepository
  implements EncryptedSecretRepository
{
  private constructor(private readonly db: SQLiteDatabase) {}

  static async open(vaultId: string): Promise<EncryptedSecretRepository> {
    try {
      const db = openDatabaseSync('keywarden-vault.db')
      db.execSync(`
        CREATE TABLE IF NOT EXISTS vault_meta (
          id TEXT PRIMARY KEY NOT NULL,
          schema_version INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `)
      db.execSync(`
        CREATE TABLE IF NOT EXISTS encrypted_secret (
          id TEXT PRIMARY KEY NOT NULL,
          vault_id TEXT NOT NULL,
          cipher_version INTEGER NOT NULL,
          nonce TEXT NOT NULL,
          ciphertext TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          deleted_at INTEGER
        )
      `)
      db.execSync(`
        CREATE INDEX IF NOT EXISTS encrypted_secret_vault_id_idx
          ON encrypted_secret(vault_id)
      `)
      db.execSync(`
        CREATE TABLE IF NOT EXISTS transfer_receipt (
          id TEXT PRIMARY KEY NOT NULL,
          vault_id TEXT NOT NULL,
          pairing_id_hash TEXT NOT NULL,
          transfer_id_hash TEXT NOT NULL,
          bundle_sha256 TEXT NOT NULL,
          imported_count INTEGER NOT NULL,
          skipped_count INTEGER NOT NULL,
          sender_nostr_pubkey_hash TEXT NOT NULL,
          committed_at INTEGER NOT NULL
        )
      `)
      db.execSync(`
        CREATE UNIQUE INDEX IF NOT EXISTS transfer_receipt_digest_idx
          ON transfer_receipt(vault_id, bundle_sha256)
      `)
      const now = Date.now()
      db.runSync(
        `INSERT OR IGNORE INTO vault_meta (id, schema_version, created_at, updated_at)
         VALUES (?, 1, ?, ?)`,
        vaultId,
        now,
        now,
      )

      return new ExpoSqliteEncryptedSecretRepository(db)
    } catch (cause) {
      console.warn(
        'Keywarden SQLite unavailable, using SecureStore repository:',
        cause instanceof Error ? cause.message : String(cause),
      )
      return new SecureStoreEncryptedSecretRepository(vaultId)
    }
  }

  async list(vaultId: string): Promise<EncryptedSecretRow[]> {
    const rows = this.db.getAllSync<EncryptedSecretSqlRow>(
      `SELECT id, vault_id, cipher_version, nonce, ciphertext, created_at, updated_at, deleted_at
       FROM encrypted_secret
       WHERE vault_id = ? AND deleted_at IS NULL
       ORDER BY updated_at DESC`,
      vaultId,
    )

    return rows.map(rowFromSql)
  }

  async runImportTransaction<T>(
    operation: (transaction: EncryptedSecretTransaction) => Promise<T>,
  ): Promise<T> {
    this.db.execSync('BEGIN IMMEDIATE')
    try {
      const result = await operation(
        new ExpoSqliteEncryptedSecretTransaction(this.db),
      )
      this.db.execSync('COMMIT')
      return result
    } catch (cause) {
      this.db.execSync('ROLLBACK')
      throw cause
    }
  }
}

class ExpoSqliteEncryptedSecretTransaction
  implements EncryptedSecretTransaction
{
  constructor(private readonly db: SQLiteDatabase) {}

  async findExistingPublicAddresses(
    vaultId: string,
    addresses: readonly string[],
    decryptRecord: (row: EncryptedSecretRow) => Promise<SecretRecordV1>,
  ): Promise<Set<string>> {
    const wanted = new Set(addresses)
    const existing = new Set<string>()
    const rows = this.db.getAllSync<EncryptedSecretSqlRow>(
      `SELECT id, vault_id, cipher_version, nonce, ciphertext, created_at, updated_at, deleted_at
       FROM encrypted_secret
       WHERE vault_id = ? AND deleted_at IS NULL`,
      vaultId,
    )

    for (const row of rows) {
      const record = await decryptRecord(rowFromSql(row))
      if (wanted.has(record.publicAddress)) {
        existing.add(record.publicAddress)
      }
    }

    return existing
  }

  async insertSecret(row: EncryptedSecretRow): Promise<void> {
    this.db.runSync(
      `INSERT INTO encrypted_secret
       (id, vault_id, cipher_version, nonce, ciphertext, created_at, updated_at, deleted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      row.id,
      row.vaultId,
      row.cipherVersion,
      row.nonce,
      row.ciphertext,
      row.createdAt,
      row.updatedAt,
      row.deletedAt ?? null,
    )
  }

  async insertTransferReceipt(receipt: TransferReceiptRow): Promise<void> {
    this.db.runSync(
      `INSERT OR IGNORE INTO transfer_receipt
       (id, vault_id, pairing_id_hash, transfer_id_hash, bundle_sha256, imported_count, skipped_count, sender_nostr_pubkey_hash, committed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      receipt.id,
      receipt.vaultId,
      receipt.pairingIdHash,
      receipt.transferIdHash,
      receipt.bundleSha256,
      receipt.importedCount,
      receipt.skippedCount,
      receipt.senderNostrPubkeyHash,
      receipt.committedAt,
    )
  }
}

class SecureStoreEncryptedSecretRepository
  implements EncryptedSecretRepository
{
  constructor(private readonly vaultId: string) {}

  async list(vaultId: string): Promise<EncryptedSecretRow[]> {
    if (vaultId !== this.vaultId) {
      return []
    }

    const rows = await loadSecureStoreRows(vaultId)
    return rows
      .filter((row) => !row.deletedAt)
      .sort((left, right) => right.updatedAt - left.updatedAt)
  }

  async runImportTransaction<T>(
    operation: (transaction: EncryptedSecretTransaction) => Promise<T>,
  ): Promise<T> {
    const state = await loadSecureStoreState(this.vaultId)
    const transaction = new SecureStoreEncryptedSecretTransaction(state)
    const result = await operation(transaction)
    await saveSecureStoreState(this.vaultId, state)

    return result
  }
}

type SecureStoreRepositoryState = {
  receipts: TransferReceiptRow[]
  rows: EncryptedSecretRow[]
}

class SecureStoreEncryptedSecretTransaction
  implements EncryptedSecretTransaction
{
  constructor(private readonly state: SecureStoreRepositoryState) {}

  async findExistingPublicAddresses(
    vaultId: string,
    addresses: readonly string[],
    decryptRecord: (row: EncryptedSecretRow) => Promise<SecretRecordV1>,
  ): Promise<Set<string>> {
    const wanted = new Set(addresses)
    const existing = new Set<string>()
    const rows = this.state.rows.filter(
      (row) => row.vaultId === vaultId && !row.deletedAt,
    )

    for (const row of rows) {
      const record = await decryptRecord(row)
      if (wanted.has(record.publicAddress)) {
        existing.add(record.publicAddress)
      }
    }

    return existing
  }

  async insertSecret(row: EncryptedSecretRow): Promise<void> {
    this.state.rows.push(row)
  }

  async insertTransferReceipt(receipt: TransferReceiptRow): Promise<void> {
    const exists = this.state.receipts.some(
      (candidate) =>
        candidate.bundleSha256 === receipt.bundleSha256 &&
        candidate.vaultId === receipt.vaultId,
    )
    if (!exists) {
      this.state.receipts.push(receipt)
    }
  }
}

async function loadSecureStoreRows(
  vaultId: string,
): Promise<EncryptedSecretRow[]> {
  const ids = await readSecureStoreJson<string[]>(recordIndexKey(vaultId), [])
  const rows = await Promise.all(
    ids.map((id) =>
      readSecureStoreJson<EncryptedSecretRow | null>(
        recordRowKey(vaultId, id),
        null,
      ),
    ),
  )

  return rows.filter((row): row is EncryptedSecretRow => row !== null)
}

async function loadSecureStoreState(
  vaultId: string,
): Promise<SecureStoreRepositoryState> {
  return {
    receipts: await readSecureStoreJson<TransferReceiptRow[]>(
      receiptIndexKey(vaultId),
      [],
    ),
    rows: await loadSecureStoreRows(vaultId),
  }
}

async function readSecureStoreJson<T>(key: string, fallback: T): Promise<T> {
  const value = await SecureStore.getItemAsync(key)
  return value ? (JSON.parse(value) as T) : fallback
}

function receiptIndexKey(vaultId: string): string {
  return `keywarden.v1.records.${vaultId}.receipts`
}

function recordIndexKey(vaultId: string): string {
  return `keywarden.v1.records.${vaultId}.ids`
}

function recordRowKey(vaultId: string, rowId: string): string {
  return `keywarden.v1.records.${vaultId}.row.${rowId}`
}

function rowFromSql(row: EncryptedSecretSqlRow): EncryptedSecretRow {
  return {
    cipherVersion: row.cipher_version,
    ciphertext: row.ciphertext,
    createdAt: row.created_at,
    deletedAt: row.deleted_at ?? undefined,
    id: row.id,
    nonce: row.nonce,
    updatedAt: row.updated_at,
    vaultId: row.vault_id,
  }
}

async function saveSecureStoreState(
  vaultId: string,
  state: SecureStoreRepositoryState,
): Promise<void> {
  await SecureStore.setItemAsync(
    recordIndexKey(vaultId),
    JSON.stringify(state.rows.map((row) => row.id)),
  )
  await SecureStore.setItemAsync(
    receiptIndexKey(vaultId),
    JSON.stringify(state.receipts),
  )
  await Promise.all(
    state.rows.map((row) =>
      SecureStore.setItemAsync(
        recordRowKey(vaultId, row.id),
        JSON.stringify(row),
      ),
    ),
  )
}
