import type {
  KeywardenMessageBodyV1,
  SecretRecordV1,
  TransferAckV1,
} from '@keywarden/core'
import {
  ACK_WAIT_SECONDS,
  base64UrlToBytes,
  buildKeywardenUri,
  bytesToBase64Url,
  createMessageHeader,
  createTransferChunks,
  createTransferManifest,
  DEFAULT_CHUNK_PLAINTEXT_BYTES,
  DEFAULT_KEYWARDEN_RELAYS,
  MAX_IMPORT_FILES,
  MAX_TRANSFER_BUNDLE_BYTES,
  PAIRING_TTL_SECONDS,
  reassembleTransferChunks,
  serializeTransferBundleV1,
  TRANSFER_EVENT_TTL_SECONDS,
} from '@keywarden/core'
import {
  createWebCryptoAdapter,
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
  ensureUniqueSolanaAddresses,
  parseSolanaCliKeypairJson,
} from '@keywarden/solana'
import { CheckCircle2, QrCode, Send, ShieldCheck, Trash2 } from 'lucide-react'
import QRCode from 'qrcode'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

type ImportPreview = {
  error?: string
  filename: string
  label: string
  publicAddress?: string
  recordId?: string
}

type RelayStatus = Record<string, 'connected' | 'failed' | 'idle' | 'published'>

type WebSession = {
  cryptoAdapter: KeywardenCrypto
  ecdhPublicKey: Uint8Array
  keypair: ReturnType<typeof createKeywardenNostrKeypair>
  pairingId: string
  pairingSecret: Uint8Array
  relays: string[]
  sequence: number
  transport: KeywardenRelayTransport
  webPrivateKey: CryptoKey
}

type PairedSession = WebSession & {
  encryptionKey: CryptoKey
  mobileEcdhPublicKey: Uint8Array
  mobileNostrPubkey: string
  verificationKey: CryptoKey
}

const emptyRelayStatus = Object.fromEntries(
  DEFAULT_KEYWARDEN_RELAYS.map((relay) => [relay, 'idle']),
) as RelayStatus

export function KeywardenImportFeature() {
  const [ack, setAck] = useState<TransferAckV1 | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [peerConfirmed, setPeerConfirmed] = useState(false)
  const [previews, setPreviews] = useState<ImportPreview[]>([])
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null)
  const [relayText, setRelayText] = useState(
    DEFAULT_KEYWARDEN_RELAYS.join('\n'),
  )
  const [relayStatus, setRelayStatus] = useState<RelayStatus>(emptyRelayStatus)
  const [sessionState, setSessionState] = useState('idle')
  const [transferDigest, setTransferDigest] = useState<string | null>(null)
  const [verificationCode, setVerificationCode] = useState<string | null>(null)

  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const localConfirmedRef = useRef(false)
  const pairedSessionRef = useRef<PairedSession | null>(null)
  const recordsRef = useRef<SecretRecordV1[]>([])
  const sessionRef = useRef<WebSession | null>(null)

  const validPreviewCount = previews.filter(
    (preview) => preview.publicAddress,
  ).length
  const canSelectFiles =
    sessionState === 'ready-for-files' || sessionState === 'review'
  const canTransfer =
    sessionState === 'review' &&
    previews.length > 0 &&
    previews.every((preview) => preview.publicAddress && !preview.error)

  const relayDomains = useMemo(
    () => parseRelayText(relayText).map((relay) => new URL(relay).host),
    [relayText],
  )

  const destroySession = useCallback(() => {
    sessionRef.current?.transport.close()
    sessionRef.current?.pairingSecret.fill(0)
    recordsRef.current = []
    fileInputRef.current?.form?.reset()
    localConfirmedRef.current = false
    pairedSessionRef.current = null
    sessionRef.current = null
  }, [])

  useEffect(
    () => () => {
      destroySession()
    },
    [destroySession],
  )

  async function startSession() {
    destroySession()
    setAck(null)
    setError(null)
    setPeerConfirmed(false)
    setPreviews([])
    setSessionState('creating-session')
    setTransferDigest(null)
    setVerificationCode(null)

    try {
      const cryptoAdapter = createWebCryptoAdapter(globalThis.crypto)
      const keypair = createKeywardenNostrKeypair()
      const ecdhKeyPair = await cryptoAdapter.generateEcdhKeyPair()
      const ecdhPublicKey = await cryptoAdapter.exportEcdhPublicKey(
        ecdhKeyPair.publicKey,
      )
      const pairingId = bytesToBase64Url(cryptoAdapter.randomBytes(16))
      const pairingSecret = cryptoAdapter.randomBytes(32)
      const expiresAt = Math.floor(Date.now() / 1000) + PAIRING_TTL_SECONDS
      const relays = parseRelayText(relayText)
      const transport = new KeywardenRelayTransport()
      const session: WebSession = {
        cryptoAdapter,
        ecdhPublicKey,
        keypair,
        pairingId,
        pairingSecret,
        relays,
        sequence: 0,
        transport,
        webPrivateKey: ecdhKeyPair.privateKey,
      }
      const qrUri = buildKeywardenUri({
        expiresAt,
        mode: 'web-to-mobile-import',
        pairingId,
        pairingSecret: bytesToBase64Url(pairingSecret),
        protocol: 'keywarden',
        relays,
        version: 1,
        webEcdhPublicKey: bytesToBase64Url(ecdhPublicKey),
        webNostrPubkey: keypair.publicKey,
      })

      setQrDataUrl(await QRCode.toDataURL(qrUri, { margin: 1, width: 280 }))
      sessionRef.current = session

      await transport.connect(relays)
      setRelayStatus(
        Object.fromEntries(
          relays.map((relay) => [relay, 'connected']),
        ) as RelayStatus,
      )
      const duplicates = new DuplicateTracker()

      transport.subscribe({
        filter: createKeywardenSubscriptionFilter({
          pairingId,
          receiverNostrPubkey: keypair.publicKey,
          sessionExpiresAtUnixSeconds: expiresAt,
          sessionStartedAtUnixSeconds: Math.floor(Date.now() / 1000),
        }),
        onEvent: (event) => {
          if (!duplicates.accept(event)) {
            return
          }
          void handleSessionEvent(event)
        },
        relays,
      })

      setSessionState('awaiting-mobile')
    } catch {
      setError('Unable to create a local pairing session.')
      setSessionState('error')
    }
  }

  async function confirmCodesMatch() {
    const paired = pairedSessionRef.current
    if (!paired) {
      return
    }

    localConfirmedRef.current = true
    await publishBody({
      header: nextHeader(paired, 'pairing.confirmed'),
    })

    if (peerConfirmed) {
      setSessionState('ready-for-files')
    } else {
      setSessionState('awaiting-peer-confirmation')
    }
  }

  async function handleFiles(files: FileList | null) {
    if (!files || !canSelectFiles) {
      return
    }

    setError(null)
    setSessionState('parsing-files')

    const selectedFiles = Array.from(files).slice(0, MAX_IMPORT_FILES)
    const nextRecords: SecretRecordV1[] = []
    const nextPreviews: ImportPreview[] = []

    for (const file of selectedFiles) {
      try {
        const parsed = parseSolanaCliKeypairJson({
          content: await file.text(),
          filename: file.name,
        })
        nextRecords.push(parsed.record)
        nextPreviews.push({
          filename: file.name,
          label: parsed.record.label,
          publicAddress: parsed.record.publicAddress,
          recordId: parsed.record.id,
        })
        parsed.secretKey.fill(0)
      } catch {
        nextPreviews.push({
          error: 'Invalid Solana CLI keypair JSON file.',
          filename: file.name,
          label: file.name,
        })
      }
    }

    try {
      ensureUniqueSolanaAddresses(nextRecords)
      recordsRef.current = nextRecords
      setPreviews(nextPreviews)
      setSessionState('review')
    } catch {
      recordsRef.current = []
      setPreviews(
        nextPreviews.map((preview) => ({
          ...preview,
          error: preview.error ?? 'Duplicate address in selected files.',
        })),
      )
      setSessionState('review')
    }
  }

  async function handleSessionEvent(
    event: Parameters<typeof validateKeywardenEvent>[0]['event'],
  ) {
    const session = sessionRef.current
    if (!session) {
      return
    }

    try {
      const verifiedEvent = validateKeywardenEvent({
        event,
        expectedPairingId: session.pairingId,
        expectedRecipientNostrPubkey: session.keypair.publicKey,
      })
      const envelope = parseKeywardenEventEnvelope(verifiedEvent)

      let paired = pairedSessionRef.current
      if (!paired) {
        if (!envelope.senderEcdhPublicKey) {
          throw new Error('PROTOCOL_VIOLATION')
        }

        const mobileEcdhPublicKeyBytes = base64UrlToBytes(
          envelope.senderEcdhPublicKey,
        )
        const mobileEcdhPublicKey =
          await session.cryptoAdapter.importEcdhPublicKey(
            mobileEcdhPublicKeyBytes,
          )
        const keys = await session.cryptoAdapter.derivePairingKeys({
          mobileEcdhPublicKey: mobileEcdhPublicKeyBytes,
          mobileNostrPubkey: verifiedEvent.pubkey,
          ownPrivateKey: session.webPrivateKey,
          pairingId: session.pairingId,
          pairingSecret: session.pairingSecret,
          peerPublicKey: mobileEcdhPublicKey,
          webEcdhPublicKey: session.ecdhPublicKey,
          webNostrPubkey: session.keypair.publicKey,
        })
        paired = {
          ...session,
          encryptionKey: keys.encryptionKey,
          mobileEcdhPublicKey: mobileEcdhPublicKeyBytes,
          mobileNostrPubkey: verifiedEvent.pubkey,
          verificationKey: keys.verificationKey,
        }
        pairedSessionRef.current = paired
        setVerificationCode(
          await deriveVerificationCode(
            session.cryptoAdapter,
            keys.verificationKey,
          ),
        )
      }

      const message = await decryptProtocolMessage({
        cryptoAdapter: paired.cryptoAdapter,
        encryptionKey: paired.encryptionKey,
        envelope,
        pairingId: paired.pairingId,
        recipientNostrPubkey: paired.keypair.publicKey,
        senderNostrPubkey: verifiedEvent.pubkey,
      })

      if (message.header.type === 'pairing.request') {
        await publishBody({
          header: nextHeader(paired, 'pairing.ready'),
        })
        setSessionState('awaiting-local-confirmation')
        return
      }

      if (message.header.type === 'pairing.confirmed') {
        setPeerConfirmed(true)
        setSessionState(
          localConfirmedRef.current
            ? 'ready-for-files'
            : 'awaiting-local-confirmation',
        )
        return
      }

      if (message.header.type === 'transfer.ack') {
        const ackMessage = message as Extract<
          KeywardenMessageBodyV1,
          { ack: TransferAckV1 }
        >
        if (ackMessage.ack.bundleSha256 !== transferDigest) {
          throw new Error('DIGEST_MISMATCH')
        }
        setAck(ackMessage.ack)
        setSessionState('complete')
        recordsRef.current = []
      }
    } catch {
      setError('Received an invalid or unauthenticated pairing message.')
      setSessionState('error')
    }
  }

  function nextHeader(
    session: PairedSession,
    type: KeywardenMessageBodyV1['header']['type'],
  ) {
    const header = createMessageHeader({
      pairingId: session.pairingId,
      recipientNostrPubkey: session.mobileNostrPubkey,
      senderNostrPubkey: session.keypair.publicKey,
      sequence: session.sequence,
      type,
    })
    session.sequence += 1
    return header
  }

  async function publishBody(body: KeywardenMessageBodyV1) {
    const paired = pairedSessionRef.current
    if (!paired) {
      throw new Error('No paired session')
    }

    const envelope = await encryptProtocolMessage({
      body,
      cryptoAdapter: paired.cryptoAdapter,
      encryptionKey: paired.encryptionKey,
    })
    const event = createKeywardenEvent({
      envelope,
      expiresAtUnixSeconds:
        Math.floor(Date.now() / 1000) + TRANSFER_EVENT_TTL_SECONDS,
      pairingId: paired.pairingId,
      recipientNostrPubkey: paired.mobileNostrPubkey,
      secretKey: paired.keypair.secretKey,
    })
    const result = await paired.transport.publish(paired.relays, event)

    setRelayStatus((current) => ({
      ...current,
      ...Object.fromEntries(
        result.acceptedBy.map((relay) => [relay, 'published']),
      ),
    }))

    if (result.acceptedBy.length === 0) {
      throw new Error('RELAY_UNAVAILABLE')
    }
  }

  async function transferRecords() {
    const paired = pairedSessionRef.current
    if (!paired) {
      return
    }

    setError(null)
    setSessionState('publishing')

    try {
      const bundle = {
        createdAt: new Date().toISOString(),
        records: recordsRef.current,
        schema: 'keywarden.transfer-bundle' as const,
        transferId: bytesToBase64Url(paired.cryptoAdapter.randomBytes(16)),
        version: 1 as const,
      }
      const bundleBytes = serializeTransferBundleV1(bundle)
      if (bundleBytes.byteLength > MAX_TRANSFER_BUNDLE_BYTES) {
        throw new Error('TRANSFER_TOO_LARGE')
      }

      const digest = bytesToBase64Url(
        await paired.cryptoAdapter.sha256(bundleBytes),
      )
      const chunks = createTransferChunks({
        bytes: bundleBytes,
        chunkPlaintextSize: DEFAULT_CHUNK_PLAINTEXT_BYTES,
        transferId: bundle.transferId,
      })
      reassembleTransferChunks(chunks)
      setTransferDigest(digest)

      await publishBody({
        header: nextHeader(paired, 'transfer.manifest'),
        manifest: createTransferManifest({
          bundleByteLength: bundleBytes.byteLength,
          bundleSha256: digest,
          chunkCount: chunks.length,
          recordCount: bundle.records.length,
          transferId: bundle.transferId,
        }),
      })

      for (const chunk of chunks) {
        await publishBody({
          chunk,
          header: nextHeader(paired, 'transfer.chunk'),
        })
      }

      setSessionState('awaiting-ack')
      setTimeout(() => {
        if (sessionState === 'awaiting-ack') {
          setError('Timed out waiting for mobile acknowledgement.')
        }
      }, ACK_WAIT_SECONDS * 1000)
    } catch {
      setError('Unable to publish the encrypted transfer.')
      setSessionState('error')
    }
  }

  function updateLabel(recordId: string, label: string) {
    recordsRef.current = recordsRef.current.map((record) =>
      record.id === recordId
        ? {
            ...record,
            label: label.slice(0, 128),
          }
        : record,
    )
    setPreviews((current) =>
      current.map((preview) =>
        preview.recordId === recordId
          ? {
              ...preview,
              label,
            }
          : preview,
      ),
    )
  }

  return (
    <main className="mx-auto grid max-w-6xl gap-6 px-4 py-6">
      <section className="grid gap-3 border p-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="size-5" />
          <h1 className="font-semibold text-2xl">Keywarden Import</h1>
        </div>
        <p className="max-w-3xl text-muted-foreground text-sm">
          Pair this browser with Keywarden on Seeker, then transfer Solana CLI
          keypair files as encrypted Nostr messages. Keep the original backups;
          this prototype is not audited recovery software.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => void startSession()}>
            <QrCode />
            Start secure transfer
          </Button>
          <Button onClick={destroySession} variant="outline">
            <Trash2 />
            Destroy session
          </Button>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <div className="grid gap-3 border p-4">
          <h2 className="font-medium text-lg">Pairing</h2>
          {qrDataUrl ? (
            <img
              alt="Keywarden pairing QR code"
              className="aspect-square w-full border bg-white p-3"
              src={qrDataUrl}
            />
          ) : (
            <div className="grid aspect-square place-items-center border text-muted-foreground text-sm">
              No active QR
            </div>
          )}
          <div className="grid gap-1 text-sm">
            <div>Status: {sessionState}</div>
            <div>Relays: {relayDomains.join(', ')}</div>
            {verificationCode ? (
              <div className="font-mono text-3xl tracking-normal">
                {verificationCode}
              </div>
            ) : null}
          </div>
          <div className="grid gap-1 text-xs">
            {Object.entries(relayStatus).map(([relay, status]) => (
              <div className="flex justify-between gap-2" key={relay}>
                <span className="truncate">{relay}</span>
                <span>{status}</span>
              </div>
            ))}
          </div>
          <Button
            disabled={!verificationCode || sessionState === 'ready-for-files'}
            onClick={() => void confirmCodesMatch()}
            variant="secondary"
          >
            <CheckCircle2 />
            Codes match
          </Button>
          <label className="grid gap-1 text-xs">
            Relay URLs
            <textarea
              className="min-h-20 border bg-background p-2 font-mono text-xs outline-none focus-visible:ring-1 focus-visible:ring-ring"
              disabled={sessionState !== 'idle' && sessionState !== 'error'}
              onChange={(event) => setRelayText(event.currentTarget.value)}
              value={relayText}
            />
          </label>
        </div>

        <div className="grid gap-4">
          <form className="grid gap-3 border p-4">
            <h2 className="font-medium text-lg">Select Keys</h2>
            <Input
              disabled={!canSelectFiles}
              multiple
              onChange={(event) => void handleFiles(event.currentTarget.files)}
              ref={fileInputRef}
              type="file"
            />
            <p className="text-muted-foreground text-xs">
              Files are read locally after pairing. Secret arrays are never
              rendered, stored in browser storage, or sent to the API.
            </p>
          </form>

          <section className="grid gap-3 border p-4">
            <div className="flex items-center justify-between gap-3">
              <h2 className="font-medium text-lg">Review</h2>
              <span className="text-muted-foreground text-sm">
                {validPreviewCount} valid files
              </span>
            </div>
            <div className="grid max-h-[420px] gap-2 overflow-auto">
              {previews.length === 0 ? (
                <div className="text-muted-foreground text-sm">
                  No files selected.
                </div>
              ) : (
                previews.map((preview) => (
                  <div
                    className="grid gap-2 border p-3"
                    key={preview.recordId ?? preview.filename}
                  >
                    <div className="text-muted-foreground text-xs">
                      {preview.filename}
                    </div>
                    <Input
                      disabled={!preview.recordId}
                      onChange={(event) =>
                        preview.recordId
                          ? updateLabel(
                              preview.recordId,
                              event.currentTarget.value,
                            )
                          : undefined
                      }
                      value={preview.label}
                    />
                    <div className="break-all font-mono text-xs">
                      {preview.publicAddress ?? preview.error}
                    </div>
                  </div>
                ))
              )}
            </div>
            <Button
              disabled={!canTransfer}
              onClick={() => void transferRecords()}
            >
              <Send />
              Transfer {validPreviewCount} keys
            </Button>
          </section>
        </div>
      </section>

      {sessionState === 'awaiting-ack' ? (
        <section className="border p-4 text-sm">
          Waiting for an authenticated mobile acknowledgement.
        </section>
      ) : null}

      {ack ? (
        <section className="grid gap-2 border p-4 text-sm">
          <div className="flex items-center gap-2 font-medium">
            <CheckCircle2 className="size-4" />
            Transfer committed
          </div>
          <div>
            Imported {ack.importedCount}; skipped {ack.skippedCount}. Verify the
            mobile vault before deleting any original backups.
          </div>
        </section>
      ) : null}

      {error ? (
        <section className="border border-destructive p-4 text-destructive text-sm">
          {error}
        </section>
      ) : null}

      <section className="grid gap-2 border p-4 text-muted-foreground text-xs">
        <div>
          Use a trusted browser profile and disable unnecessary extensions.
        </div>
        <div>
          Do not perform imports on shared, managed, or compromised machines.
        </div>
        <div>
          Anyone who controls this page while keys are loaded can steal them.
        </div>
      </section>
    </main>
  )
}

function parseRelayText(value: string): string[] {
  const relays = value
    .split(/\s+/u)
    .map((relay) => relay.trim())
    .filter(Boolean)

  return relays.length > 0 ? relays.slice(0, 5) : [...DEFAULT_KEYWARDEN_RELAYS]
}
