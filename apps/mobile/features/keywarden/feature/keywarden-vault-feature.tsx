import { Ionicons } from '@expo/vector-icons'
import type {
  KeywardenMessageBodyV1,
  PairingQrV1,
  SecretRecordV1,
  TransferChunkV1,
  TransferManifestV1,
} from '@keywarden/core'
import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToUtf8,
  createMessageHeader,
  parseKeywardenUri,
  reassembleTransferChunks,
  TransferBundleV1Schema,
} from '@keywarden/core'
import {
  decryptProtocolMessage,
  deriveVerificationCode,
  encryptProtocolMessage,
  type KeywardenCrypto,
} from '@keywarden/crypto'
import {
  createKeywardenEvent,
  createKeywardenNostrKeypair,
  createKeywardenSubscriptionFilter,
  DuplicateTracker,
  KeywardenRelayTransport,
  parseKeywardenEventEnvelope,
  validateKeywardenEvent,
} from '@keywarden/nostr'
import {
  decryptVaultRows,
  type EncryptedSecretRepository,
  importTransferBundle,
  type VaultSession,
} from '@keywarden/vault'
import { CameraView, useCameraPermissions } from 'expo-camera'
import * as Linking from 'expo-linking'
import * as ScreenCapture from 'expo-screen-capture'
import { Button, Card } from 'heroui-native'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AppState, Text, TextInput, View } from 'react-native'
import { ShellUiScrollView } from '@/features/shell/ui/shell-ui-scroll-view'

import { ExpoSqliteEncryptedSecretRepository } from '../data-access/keywarden-sqlite-repository'
import { loadOrCreateVaultSession } from '../data-access/keywarden-vault-storage'

type PairingSession = {
  chunks: Map<number, TransferChunkV1>
  cryptoAdapter: KeywardenCrypto
  encryptionKey: CryptoKey
  keypair: ReturnType<typeof createKeywardenNostrKeypair>
  manifest?: TransferManifestV1
  mobileEcdhPublicKey: string
  pairing: PairingQrV1
  peerConfirmed: boolean
  sequence: number
  transport: KeywardenRelayTransport
  verificationKey: CryptoKey
}

type RecordSummary = {
  importedAt: string
  label: string
  publicAddress: string
}

type VaultRuntime = {
  cryptoAdapter: KeywardenCrypto
  repository: EncryptedSecretRepository
  session: VaultSession
}

type KeywardenVaultFeatureProps = {
  initialPairingUri?: string
}

export function KeywardenVaultFeature({
  initialPairingUri,
}: KeywardenVaultFeatureProps) {
  const [cameraPermission, requestCameraPermission] = useCameraPermissions()
  const [error, setError] = useState<string | null>(null)
  const [importSummary, setImportSummary] = useState<RecordSummary[]>([])
  const [manualUri, setManualUri] = useState('')
  const [records, setRecords] = useState<RecordSummary[]>([])
  const [relayDomains, setRelayDomains] = useState<string[]>([])
  const [screenState, setScreenState] = useState('locked')
  const [scanned, setScanned] = useState(false)
  const [verificationCode, setVerificationCode] = useState<string | null>(null)

  const handlePairingUriRef = useRef<(uri: string) => void>(() => {})
  const handledPairingUriRef = useRef<string | null>(null)
  const localConfirmedRef = useRef(false)
  const pairingRef = useRef<PairingSession | null>(null)
  const pendingBundleRef = useRef<{
    bundle: ReturnType<typeof TransferBundleV1Schema.parse>
    bundleSha256: string
  } | null>(null)
  const pendingPairingUriRef = useRef<string | null>(null)
  const runtimeRef = useRef<VaultRuntime | null>(null)

  const canConfirm = Boolean(verificationCode && pairingRef.current)
  const canImport = screenState === 'import-review' && pendingBundleRef.current

  const statusText = useMemo(() => {
    if (screenState === 'ready') {
      return 'Vault unlocked'
    }
    return screenState
  }, [screenState])

  handlePairingUriRef.current = (uri: string) => {
    void handlePairingUri(uri)
  }

  const lockVault = useCallback(() => {
    pairingRef.current?.transport.close()
    handledPairingUriRef.current = null
    pairingRef.current = null
    pendingBundleRef.current = null
    pendingPairingUriRef.current = null
    runtimeRef.current = null
    localConfirmedRef.current = false
    setImportSummary([])
    setRecords([])
    setRelayDomains([])
    setScanned(false)
    setVerificationCode(null)
    setScreenState('locked')
  }, [])

  useEffect(() => {
    void ScreenCapture.preventScreenCaptureAsync()
    const subscription = AppState.addEventListener('change', (state) => {
      if (state !== 'active') {
        lockVault()
      }
    })

    return () => {
      subscription.remove()
      void ScreenCapture.allowScreenCaptureAsync()
      pairingRef.current?.transport.close()
    }
  }, [lockVault])

  useEffect(() => {
    function handleLink(url: string | null) {
      if (!url?.startsWith('keywarden:/v1/pair')) {
        return
      }
      if (handledPairingUriRef.current === url) {
        return
      }

      handledPairingUriRef.current = url
      setManualUri(url)

      if (runtimeRef.current) {
        handlePairingUriRef.current(url)
        return
      }

      pendingPairingUriRef.current = url
    }

    handleLink(initialPairingUri ?? null)
    void Linking.getInitialURL().then(handleLink)
    const subscription = Linking.addEventListener('url', (event) => {
      handleLink(event.url)
    })

    return () => {
      subscription.remove()
    }
  }, [initialPairingUri])

  async function confirmCodesMatch() {
    const pairing = pairingRef.current
    if (!pairing) {
      return
    }

    localConfirmedRef.current = true
    await publishBody({
      header: nextHeader(pairing, 'pairing.confirmed'),
    })
    setScreenState(
      pairing.peerConfirmed
        ? 'waiting-for-manifest'
        : 'awaiting-peer-confirmation',
    )
  }

  async function commitImport() {
    const runtime = runtimeRef.current
    const pairing = pairingRef.current
    const pending = pendingBundleRef.current
    if (!runtime || !pairing || !pending) {
      return
    }

    setScreenState('committing')
    setError(null)

    try {
      const result = await importTransferBundle({
        bundle: pending.bundle,
        bundleSha256: pending.bundleSha256,
        cryptoAdapter: runtime.cryptoAdapter,
        pairingId: pairing.pairing.pairingId,
        repository: runtime.repository,
        senderNostrPubkey: pairing.pairing.webNostrPubkey,
        session: runtime.session,
      })
      setScreenState('sending-ack')
      await publishBody({
        ack: result.ack,
        header: nextHeader(pairing, 'transfer.ack'),
      })
      pendingBundleRef.current = null
      setImportSummary([])
      await refreshRecords()
      setScreenState('complete')
    } catch {
      setError('Unable to commit the encrypted transfer.')
      setScreenState('error')
    }
  }

  async function handlePairingUri(uri: string) {
    const runtime = runtimeRef.current
    if (!runtime) {
      setError('Unlock or create the vault before pairing.')
      return
    }

    pairingRef.current?.transport.close()
    pairingRef.current = null
    pendingBundleRef.current = null
    localConfirmedRef.current = false
    setImportSummary([])
    setRelayDomains([])
    setVerificationCode(null)
    setError(null)
    setScanned(true)
    setScreenState('connecting')

    try {
      const pairing = parseKeywardenUri(uri)
      const keypair = createKeywardenNostrKeypair()
      const ecdh = await runtime.cryptoAdapter.generateEcdhKeyPair()
      const mobileEcdhPublicKeyBytes =
        await runtime.cryptoAdapter.exportEcdhPublicKey(ecdh.publicKey)
      const webEcdhPublicKeyBytes = base64UrlToBytes(pairing.webEcdhPublicKey)
      const keys = await runtime.cryptoAdapter.derivePairingKeys({
        mobileEcdhPublicKey: mobileEcdhPublicKeyBytes,
        mobileNostrPubkey: keypair.publicKey,
        ownPrivateKey: ecdh.privateKey,
        pairingId: pairing.pairingId,
        pairingSecret: base64UrlToBytes(pairing.pairingSecret),
        peerPublicKey: await runtime.cryptoAdapter.importEcdhPublicKey(
          webEcdhPublicKeyBytes,
        ),
        webEcdhPublicKey: webEcdhPublicKeyBytes,
        webNostrPubkey: pairing.webNostrPubkey,
      })
      const transport = new KeywardenRelayTransport()
      const nextPairing: PairingSession = {
        chunks: new Map(),
        cryptoAdapter: runtime.cryptoAdapter,
        encryptionKey: keys.encryptionKey,
        keypair,
        mobileEcdhPublicKey: bytesToBase64Url(mobileEcdhPublicKeyBytes),
        pairing,
        peerConfirmed: false,
        sequence: 0,
        transport,
        verificationKey: keys.verificationKey,
      }
      pairingRef.current = nextPairing
      setRelayDomains(pairing.relays.map((relay) => new URL(relay).host))
      setVerificationCode(
        await deriveVerificationCode(
          runtime.cryptoAdapter,
          keys.verificationKey,
        ),
      )

      await transport.connect(pairing.relays)
      const duplicates = new DuplicateTracker()
      transport.subscribe({
        filter: createKeywardenSubscriptionFilter({
          pairingId: pairing.pairingId,
          receiverNostrPubkey: keypair.publicKey,
          sessionExpiresAtUnixSeconds: pairing.expiresAt,
          sessionStartedAtUnixSeconds: Math.floor(Date.now() / 1000),
        }),
        onEvent: (event) => {
          if (!duplicates.accept(event)) {
            return
          }
          void handleSessionEvent(event)
        },
        relays: pairing.relays,
      })

      await publishBody(
        {
          device: {
            appVersion: '0.1.0',
            deviceId: runtime.session.vaultId,
            displayName: 'Solana Seeker',
            platform: 'android',
          },
          header: nextHeader(nextPairing, 'pairing.request'),
        },
        nextPairing.mobileEcdhPublicKey,
      )
      setScreenState('awaiting-local-confirmation')
    } catch {
      pairingRef.current?.transport.close()
      pairingRef.current = null
      pendingBundleRef.current = null
      localConfirmedRef.current = false
      setError('Invalid or expired Keywarden pairing QR.')
      setScreenState('ready')
      setScanned(false)
    }
  }

  async function handleSessionEvent(
    event: Parameters<typeof validateKeywardenEvent>[0]['event'],
  ) {
    const pairing = pairingRef.current
    if (!pairing) {
      return
    }

    try {
      const verified = validateKeywardenEvent({
        event,
        expectedPairingId: pairing.pairing.pairingId,
        expectedRecipientNostrPubkey: pairing.keypair.publicKey,
      })
      const envelope = parseKeywardenEventEnvelope(verified)
      const message = await decryptProtocolMessage({
        cryptoAdapter: pairing.cryptoAdapter,
        encryptionKey: pairing.encryptionKey,
        envelope,
        pairingId: pairing.pairing.pairingId,
        recipientNostrPubkey: pairing.keypair.publicKey,
        senderNostrPubkey: pairing.pairing.webNostrPubkey,
      })

      if (message.header.type === 'pairing.ready') {
        setScreenState('awaiting-local-confirmation')
        return
      }

      if (message.header.type === 'pairing.confirmed') {
        pairing.peerConfirmed = true
        setScreenState(
          localConfirmedRef.current
            ? 'waiting-for-manifest'
            : 'awaiting-local-confirmation',
        )
        return
      }

      if (message.header.type === 'transfer.manifest') {
        const manifestMessage = message as Extract<
          KeywardenMessageBodyV1,
          { manifest: TransferManifestV1 }
        >
        pairing.manifest = manifestMessage.manifest
        pairing.chunks.clear()
        setScreenState('receiving-chunks')
        return
      }

      if (message.header.type === 'transfer.chunk') {
        const chunkMessage = message as Extract<
          KeywardenMessageBodyV1,
          { chunk: TransferChunkV1 }
        >
        pairing.chunks.set(chunkMessage.chunk.chunkIndex, chunkMessage.chunk)
        await maybeBuildImportReview(pairing)
      }
    } catch {
      setError('Received an invalid or unauthenticated transfer message.')
      setScreenState('error')
    }
  }

  async function loadVault() {
    setError(null)
    setScreenState('unlocking')

    try {
      const loaded = await loadOrCreateVaultSession()
      const repository = await ExpoSqliteEncryptedSecretRepository.open(
        loaded.session.vaultId,
      )
      runtimeRef.current = {
        cryptoAdapter: loaded.cryptoAdapter,
        repository,
        session: loaded.session,
      }
      await refreshRecords()
      const pendingPairingUri = pendingPairingUriRef.current
      if (pendingPairingUri) {
        pendingPairingUriRef.current = null
        await handlePairingUri(pendingPairingUri)
        return
      }
      setScreenState('ready')
    } catch (cause) {
      const message = describeVaultUnlockError(cause)
      console.warn(
        'Keywarden vault unlock failed:',
        cause instanceof Error ? cause.message : message,
      )
      setError(message)
      setScreenState('error')
    }
  }

  async function maybeBuildImportReview(pairing: PairingSession) {
    const manifest = pairing.manifest
    if (!manifest || pairing.chunks.size !== manifest.chunkCount) {
      return
    }

    setScreenState('validating')
    const bytes = reassembleTransferChunks([...pairing.chunks.values()])
    const digest = bytesToBase64Url(await pairing.cryptoAdapter.sha256(bytes))

    if (
      digest !== manifest.bundleSha256 ||
      bytes.byteLength !== manifest.bundleByteLength
    ) {
      throw new Error('DIGEST_MISMATCH')
    }

    const bundle = TransferBundleV1Schema.parse(JSON.parse(bytesToUtf8(bytes)))
    pendingBundleRef.current = {
      bundle,
      bundleSha256: digest,
    }
    setImportSummary(bundle.records.map(toRecordSummary))
    setScreenState('import-review')
  }

  function nextHeader(
    pairing: PairingSession,
    type: KeywardenMessageBodyV1['header']['type'],
  ) {
    const header = createMessageHeader({
      pairingId: pairing.pairing.pairingId,
      recipientNostrPubkey: pairing.pairing.webNostrPubkey,
      senderNostrPubkey: pairing.keypair.publicKey,
      sequence: pairing.sequence,
      type,
    })
    pairing.sequence += 1
    return header
  }

  async function publishBody(
    body: KeywardenMessageBodyV1,
    senderEcdhPublicKey?: string,
  ) {
    const pairing = pairingRef.current
    if (!pairing) {
      throw new Error('No active pairing')
    }

    const envelope = await encryptProtocolMessage({
      body,
      cryptoAdapter: pairing.cryptoAdapter,
      encryptionKey: pairing.encryptionKey,
      senderEcdhPublicKey,
    })
    const event = createKeywardenEvent({
      envelope,
      expiresAtUnixSeconds: Math.floor(Date.now() / 1000) + 60 * 60,
      pairingId: pairing.pairing.pairingId,
      recipientNostrPubkey: pairing.pairing.webNostrPubkey,
      secretKey: pairing.keypair.secretKey,
    })
    const result = await pairing.transport.publish(
      pairing.pairing.relays,
      event,
    )

    if (result.acceptedBy.length === 0) {
      throw new Error('RELAY_UNAVAILABLE')
    }
  }

  async function refreshRecords() {
    const runtime = runtimeRef.current
    if (!runtime) {
      return
    }

    const rows = await runtime.repository.list(runtime.session.vaultId)
    const decrypted = await decryptVaultRows({
      cryptoAdapter: runtime.cryptoAdapter,
      rows,
      session: runtime.session,
    })
    setRecords(decrypted.map(toRecordSummary))
  }

  return (
    <ShellUiScrollView className="p-4">
      <View className="gap-4">
        <Card className="gap-3 p-4">
          <View className="flex-row items-center gap-2">
            <Ionicons name="shield-checkmark-outline" size={22} />
            <Text className="font-semibold text-foreground text-xl">
              Keywarden Vault
            </Text>
          </View>
          <Text className="text-muted text-sm">
            Local encrypted storage for imported Solana CLI keypair files. Do
            not delete original backups while this prototype is unaudited.
          </Text>
          <Text className="text-muted text-xs">Status: {statusText}</Text>
          <View className="flex-row gap-2">
            <Button onPress={() => void loadVault()}>
              <Button.Label>Unlock</Button.Label>
            </Button>
            <Button onPress={lockVault} variant="secondary">
              <Button.Label>Lock</Button.Label>
            </Button>
          </View>
        </Card>

        {screenState !== 'locked' ? (
          <Card className="gap-3 p-4">
            <Text className="font-medium text-foreground text-lg">Pair</Text>
            {cameraPermission?.granted ? (
              <CameraView
                barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
                className="h-64 overflow-hidden rounded-lg"
                onBarcodeScanned={
                  scanned
                    ? undefined
                    : (result) => void handlePairingUri(result.data)
                }
              />
            ) : (
              <Button
                onPress={() => void requestCameraPermission()}
                variant="secondary"
              >
                <Button.Label>Enable QR scanner</Button.Label>
              </Button>
            )}
            <TextInput
              autoCapitalize="none"
              autoCorrect={false}
              className="min-h-20 rounded-lg border border-border p-3 text-foreground text-xs"
              multiline
              onChangeText={setManualUri}
              placeholder="keywarden:/v1/pair?data=..."
              placeholderTextColor="#888"
              value={manualUri}
            />
            <Button
              isDisabled={!manualUri.trim()}
              onPress={() => void handlePairingUri(manualUri.trim())}
              variant="secondary"
            >
              <Button.Label>Use pasted URI</Button.Label>
            </Button>
            {verificationCode ? (
              <View className="gap-2 rounded-lg border border-border p-3">
                <Text className="text-muted text-xs">
                  Compare this code with the web importer.
                </Text>
                <Text className="font-mono text-4xl text-foreground">
                  {verificationCode}
                </Text>
                <Text className="text-muted text-xs">
                  Relays: {relayDomains.join(', ')}
                </Text>
                <Button
                  isDisabled={!canConfirm}
                  onPress={() => void confirmCodesMatch()}
                >
                  <Button.Label>Codes match</Button.Label>
                </Button>
              </View>
            ) : null}
          </Card>
        ) : null}

        {importSummary.length > 0 ? (
          <Card className="gap-3 p-4">
            <Text className="font-medium text-foreground text-lg">
              Import Review
            </Text>
            {importSummary.map((record) => (
              <View
                className="gap-1 rounded-lg border border-border p-3"
                key={record.publicAddress}
              >
                <Text className="font-medium text-foreground">
                  {record.label}
                </Text>
                <Text className="text-muted text-xs">
                  {record.publicAddress}
                </Text>
              </View>
            ))}
            <Button isDisabled={!canImport} onPress={() => void commitImport()}>
              <Button.Label>Commit encrypted import</Button.Label>
            </Button>
          </Card>
        ) : null}

        <Card className="gap-3 p-4">
          <Text className="font-medium text-foreground text-lg">
            Vault Records
          </Text>
          {records.length === 0 ? (
            <Text className="text-muted text-sm">No imported records.</Text>
          ) : (
            records.map((record) => (
              <View
                className="gap-1 rounded-lg border border-border p-3"
                key={record.publicAddress}
              >
                <Text className="font-medium text-foreground">
                  {record.label}
                </Text>
                <Text className="text-muted text-xs">
                  {record.publicAddress}
                </Text>
                <Text className="text-muted text-xs">
                  Imported {new Date(record.importedAt).toLocaleString()}
                </Text>
              </View>
            ))
          )}
        </Card>

        {error ? (
          <Card className="gap-2 border-danger-soft p-4">
            <Text className="text-danger text-sm">{error}</Text>
          </Card>
        ) : null}
      </View>
    </ShellUiScrollView>
  )
}

function describeVaultUnlockError(cause: unknown): string {
  const message = cause instanceof Error ? cause.message : ''

  if (message.includes('CRYPTO_UNAVAILABLE')) {
    return 'Required crypto primitives are unavailable on this runtime.'
  }
  if (message.includes('VAULT_UNAVAILABLE')) {
    return 'Secure storage is unavailable for the Keywarden vault.'
  }
  if (message.includes('CRYPTO_SMOKE_FAILED')) {
    return 'Required crypto runtime smoke test failed on this device.'
  }
  if (message.includes('CRYPTO_ECDH_GENERATE_FAILED')) {
    return 'Required ECDH key generation failed on this device.'
  }
  if (message.includes('CRYPTO_ECDH_EXPORT_FAILED')) {
    return 'Required ECDH public-key export failed on this device.'
  }
  if (message.includes('CRYPTO_ECDH_IMPORT_FAILED')) {
    return 'Required ECDH public-key import failed on this device.'
  }
  if (message.includes('CRYPTO_ECDH_DERIVE_FAILED')) {
    return 'Required ECDH shared-secret derivation failed on this device.'
  }
  if (message.includes('CRYPTO_PAIRING_SALT_FAILED')) {
    return 'Required pairing salt digest failed on this device.'
  }
  if (message.includes('CRYPTO_HKDF_IMPORT_FAILED')) {
    return 'Required HKDF key import failed on this device.'
  }
  if (message.includes('CRYPTO_HKDF_DERIVE_FAILED')) {
    return 'Required HKDF derivation failed on this device.'
  }
  if (message.includes('CRYPTO_PAIRING_AES_IMPORT_FAILED')) {
    return 'Required pairing AES-GCM key import failed on this device.'
  }
  if (message.includes('CRYPTO_PAIRING_HMAC_IMPORT_FAILED')) {
    return 'Required pairing HMAC key import failed on this device.'
  }
  if (message.includes('CRYPTO_PAIRING_DERIVE_FAILED')) {
    return 'Required pairing key derivation failed on this device.'
  }
  if (message.includes('CRYPTO_AES_GCM_FAILED')) {
    return 'Required AES-GCM encryption failed on this device.'
  }
  if (message.includes('CRYPTO_SHA256_FAILED')) {
    return 'Required SHA-256 digest failed on this device.'
  }
  if (message.includes('CRYPTO_HMAC_IMPORT_FAILED')) {
    return 'Required HMAC key import failed on this device.'
  }
  if (message.includes('CRYPTO_HMAC_FAILED')) {
    return 'Required HMAC-SHA-256 signing failed on this device.'
  }
  if (message.includes('VAULT_SESSION_CREATE_FAILED')) {
    return 'Unable to create the local vault encryption session.'
  }
  if (message.includes('VAULT_SESSION_IMPORT_FAILED')) {
    return 'Unable to load the local vault encryption session.'
  }
  if (message.includes('ACTIVE_VAULT_READ_FAILED')) {
    return 'Unable to read the active vault marker from secure storage.'
  }
  if (message.includes('ACTIVE_VAULT_WRITE_FAILED')) {
    return 'Unable to write the active vault marker to secure storage.'
  }
  if (message.includes('VEK_READ_FAILED')) {
    return 'Unable to read the vault encryption key from secure storage.'
  }
  if (message.includes('VEK_WRITE_FAILED')) {
    return 'Unable to write the vault encryption key to secure storage.'
  }
  if (message.includes('SQLITE_OPEN_FAILED')) {
    return 'Unable to open the encrypted-record database on this device.'
  }
  if (message.includes('SECURE_STORE_CHECK_FAILED')) {
    return 'Unable to check secure storage availability on this device.'
  }
  if (message.includes('deriveBits')) {
    return 'Required ECDH or HKDF derivation is unavailable on this runtime.'
  }
  if (message.includes('deriveKey')) {
    return 'Required vault record-key derivation is unavailable on this runtime.'
  }
  if (message.includes('export')) {
    return 'Required ECDH public-key export is unavailable on this runtime.'
  }
  if (message.includes('generateKey')) {
    return 'Required ECDH key generation is unavailable on this runtime.'
  }
  if (message.includes('importKey')) {
    return 'Required key import is unavailable on this runtime.'
  }

  return 'This runtime cannot create or unlock the Keywarden vault.'
}

function toRecordSummary(record: SecretRecordV1): RecordSummary {
  return {
    importedAt: record.importedAt,
    label: record.label,
    publicAddress: record.publicAddress,
  }
}
