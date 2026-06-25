import { bytesToBase64Url, zeroBytes } from '@keywarden/core'
import {
  createWebCryptoAdapter,
  runCryptoCapabilitySmokeTest,
} from '@keywarden/crypto'
import {
  createVaultSession,
  decodeVaultKey,
  type VaultSession,
} from '@keywarden/vault'
import * as SecureStore from 'expo-secure-store'

const ACTIVE_VAULT_ID_KEY = 'keywarden.v1.activeVaultId'

export type LoadedVaultSession = {
  cryptoAdapter: ReturnType<typeof createWebCryptoAdapter>
  session: VaultSession
}

export async function loadOrCreateVaultSession(): Promise<LoadedVaultSession> {
  const isSecureStoreAvailable = await runVaultBootstrapStep(
    'SECURE_STORE_CHECK_FAILED',
    () => SecureStore.isAvailableAsync(),
  )
  if (!isSecureStoreAvailable) {
    throw new Error('VAULT_UNAVAILABLE')
  }

  const cryptoAdapter = createWebCryptoAdapter(globalThis.crypto)
  await runVaultBootstrapStep('CRYPTO_SMOKE_FAILED', () =>
    runCryptoCapabilitySmokeTest(cryptoAdapter),
  )

  const existingVaultId = await runVaultBootstrapStep(
    'ACTIVE_VAULT_READ_FAILED',
    () => SecureStore.getItemAsync(ACTIVE_VAULT_ID_KEY),
  )
  if (existingVaultId) {
    const encodedVek = await runVaultBootstrapStep('VEK_READ_FAILED', () =>
      SecureStore.getItemAsync(vaultKeyName(existingVaultId)),
    )
    if (!encodedVek) {
      throw new Error('VAULT_UNAVAILABLE')
    }

    const vaultKeyBytes = decodeVaultKey(encodedVek)
    const loaded = await runVaultBootstrapStep(
      'VAULT_SESSION_IMPORT_FAILED',
      () =>
        createVaultSession({
          cryptoAdapter,
          vaultId: existingVaultId,
          vaultKeyBytes,
        }),
    )
    zeroBytes(vaultKeyBytes)

    return {
      cryptoAdapter,
      session: loaded.session,
    }
  }

  const created = await runVaultBootstrapStep(
    'VAULT_SESSION_CREATE_FAILED',
    () => createVaultSession({ cryptoAdapter }),
  )
  await runVaultBootstrapStep('ACTIVE_VAULT_WRITE_FAILED', () =>
    SecureStore.setItemAsync(ACTIVE_VAULT_ID_KEY, created.session.vaultId),
  )
  await runVaultBootstrapStep('VEK_WRITE_FAILED', () =>
    SecureStore.setItemAsync(
      vaultKeyName(created.session.vaultId),
      bytesToBase64Url(created.vaultKeyBytes),
    ),
  )
  zeroBytes(created.vaultKeyBytes)

  return {
    cryptoAdapter,
    session: created.session,
  }
}

function vaultKeyName(vaultId: string): string {
  return `keywarden.v1.vault.${vaultId}.vek`
}

async function runVaultBootstrapStep<T>(
  code: string,
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation()
  } catch (cause) {
    if (cause instanceof Error && cause.message.startsWith('CRYPTO_')) {
      throw cause
    }
    throw new Error(code)
  }
}
