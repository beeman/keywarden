import { describe, expect, test } from 'bun:test'
import {
  bytesToBase64Url,
  createMessageHeader,
  createTransferChunks,
  createTransferManifest,
  type KeywardenMessageBodyV1,
  parseKeywardenUri,
  reassembleTransferChunks,
  serializeTransferBundleV1,
  type TransferBundleV1,
  TransferBundleV1Schema,
} from '@keywarden/core'
import {
  createWebCryptoAdapter,
  decryptProtocolMessage,
  deriveVerificationCode,
  encryptProtocolMessage,
} from '@keywarden/crypto'
import {
  createKeywardenEvent,
  createKeywardenNostrKeypair,
  DuplicateTracker,
  getTagValue,
  type NostrEvent,
  parseKeywardenEventEnvelope,
  validateKeywardenEvent,
} from '@keywarden/nostr'
import { parseSolanaCliKeypairJson } from '@keywarden/solana'
import { ed25519 } from '@noble/curves/ed25519.js'

import {
  createVaultSession,
  decryptVaultRows,
  InMemoryEncryptedSecretRepository,
  importTransferBundle,
} from '../src'

const relays = ['wss://relay-a.example', 'wss://relay-b.example'] as const

class InMemoryRelaySet {
  private readonly events: NostrEvent[] = []
  private readonly unavailable = new Set<string>()

  constructor(unavailable: readonly string[] = []) {
    for (const relay of unavailable) {
      this.unavailable.add(relay)
    }
  }

  deliver(): NostrEvent[] {
    return [...this.events, ...this.events].reverse()
  }

  publish(event: NostrEvent): {
    acceptedBy: string[]
    rejectedBy: Array<{ relay: string; reason: string }>
  } {
    const acceptedBy: string[] = []
    const rejectedBy: Array<{ relay: string; reason: string }> = []

    for (const relay of relays) {
      if (this.unavailable.has(relay)) {
        rejectedBy.push({ reason: 'offline', relay })
        continue
      }

      acceptedBy.push(relay)
    }

    if (acceptedBy.length > 0) {
      this.events.push(event)
    }

    return { acceptedBy, rejectedBy }
  }
}

function fixtureRecord(seedValue: number, recordId: string) {
  const seed = new Uint8Array(32).fill(seedValue)
  const publicKey = ed25519.getPublicKey(seed)
  const secretKey = new Uint8Array(64)
  secretKey.set(seed)
  secretKey.set(publicKey, 32)

  return parseSolanaCliKeypairJson({
    content: JSON.stringify(Array.from(secretKey)),
    filename: `${recordId}.json`,
    recordId,
  }).record
}

function makeHeader(input: {
  pairingId: string
  recipientNostrPubkey: string
  senderNostrPubkey: string
  sequence: number
  type: KeywardenMessageBodyV1['header']['type']
}) {
  return createMessageHeader({
    pairingId: input.pairingId,
    recipientNostrPubkey: input.recipientNostrPubkey,
    senderNostrPubkey: input.senderNostrPubkey,
    sequence: input.sequence,
    type: input.type,
  })
}

describe('Keywarden encrypted transfer integration', () => {
  test('pairs, transfers reordered chunks with one relay down, commits, and acknowledges', async () => {
    const cryptoAdapter = createWebCryptoAdapter(globalThis.crypto)
    const relaySet = new InMemoryRelaySet([relays[0]])
    const webEcdh = await cryptoAdapter.generateEcdhKeyPair()
    const mobileEcdh = await cryptoAdapter.generateEcdhKeyPair()
    const webEcdhPublicKey = await cryptoAdapter.exportEcdhPublicKey(
      webEcdh.publicKey,
    )
    const mobileEcdhPublicKey = await cryptoAdapter.exportEcdhPublicKey(
      mobileEcdh.publicKey,
    )
    const webNostr = createKeywardenNostrKeypair()
    const mobileNostr = createKeywardenNostrKeypair()
    const pairingId = bytesToBase64Url(cryptoAdapter.randomBytes(16))
    const pairingSecret = cryptoAdapter.randomBytes(32)
    const expiresAtUnixSeconds = Math.floor(Date.now() / 1000) + 900
    const qrUri = `keywarden:/v1/pair?data=${bytesToBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          expiresAt: expiresAtUnixSeconds,
          mode: 'web-to-mobile-import',
          pairingId,
          pairingSecret: bytesToBase64Url(pairingSecret),
          protocol: 'keywarden',
          relays,
          version: 1,
          webEcdhPublicKey: bytesToBase64Url(webEcdhPublicKey),
          webNostrPubkey: webNostr.publicKey,
        }),
      ),
    )}`

    expect(parseKeywardenUri(qrUri).pairingId).toBe(pairingId)

    const mobileKeys = await cryptoAdapter.derivePairingKeys({
      mobileEcdhPublicKey,
      mobileNostrPubkey: mobileNostr.publicKey,
      ownPrivateKey: mobileEcdh.privateKey,
      pairingId,
      pairingSecret,
      peerPublicKey: await cryptoAdapter.importEcdhPublicKey(webEcdhPublicKey),
      webEcdhPublicKey,
      webNostrPubkey: webNostr.publicKey,
    })
    const requestBody: KeywardenMessageBodyV1 = {
      device: {
        appVersion: 'test',
        deviceId: 'seeker-test',
        displayName: 'Solana Seeker',
        platform: 'android',
      },
      header: makeHeader({
        pairingId,
        recipientNostrPubkey: webNostr.publicKey,
        senderNostrPubkey: mobileNostr.publicKey,
        sequence: 0,
        type: 'pairing.request',
      }),
    }
    const requestEnvelope = await encryptProtocolMessage({
      body: requestBody,
      cryptoAdapter,
      encryptionKey: mobileKeys.encryptionKey,
      senderEcdhPublicKey: bytesToBase64Url(mobileEcdhPublicKey),
    })
    const requestPublish = relaySet.publish(
      createKeywardenEvent({
        envelope: requestEnvelope,
        expiresAtUnixSeconds,
        pairingId,
        recipientNostrPubkey: webNostr.publicKey,
        secretKey: mobileNostr.secretKey,
      }),
    )

    expect(requestPublish.acceptedBy).toEqual([relays[1]])

    const inboundRequest = relaySet
      .deliver()
      .find((event) => getTagValue(event, 'p') === webNostr.publicKey)
    expect(inboundRequest).toBeDefined()

    const verifiedRequest = validateKeywardenEvent({
      event: inboundRequest as NostrEvent,
      expectedPairingId: pairingId,
      expectedRecipientNostrPubkey: webNostr.publicKey,
    })
    const parsedRequestEnvelope = parseKeywardenEventEnvelope(verifiedRequest)
    const webKeys = await cryptoAdapter.derivePairingKeys({
      mobileEcdhPublicKey,
      mobileNostrPubkey: mobileNostr.publicKey,
      ownPrivateKey: webEcdh.privateKey,
      pairingId,
      pairingSecret,
      peerPublicKey:
        await cryptoAdapter.importEcdhPublicKey(mobileEcdhPublicKey),
      webEcdhPublicKey,
      webNostrPubkey: webNostr.publicKey,
    })
    const webCode = await deriveVerificationCode(
      cryptoAdapter,
      webKeys.verificationKey,
    )
    const mobileCode = await deriveVerificationCode(
      cryptoAdapter,
      mobileKeys.verificationKey,
    )

    expect(webCode).toMatch(/^\d{6}$/u)
    expect(webCode).toBe(mobileCode)
    await expect(
      decryptProtocolMessage({
        cryptoAdapter,
        encryptionKey: webKeys.encryptionKey,
        envelope: parsedRequestEnvelope,
        pairingId,
        recipientNostrPubkey: webNostr.publicKey,
        senderNostrPubkey: mobileNostr.publicKey,
      }),
    ).resolves.toMatchObject({ device: { platform: 'android' } })

    let webSequence = 0
    let mobileSequence = 1
    for (const body of [
      {
        header: makeHeader({
          pairingId,
          recipientNostrPubkey: mobileNostr.publicKey,
          senderNostrPubkey: webNostr.publicKey,
          sequence: webSequence++,
          type: 'pairing.ready',
        }),
      },
      {
        header: makeHeader({
          pairingId,
          recipientNostrPubkey: mobileNostr.publicKey,
          senderNostrPubkey: webNostr.publicKey,
          sequence: webSequence++,
          type: 'pairing.confirmed',
        }),
      },
    ] satisfies KeywardenMessageBodyV1[]) {
      relaySet.publish(
        createKeywardenEvent({
          envelope: await encryptProtocolMessage({
            body,
            cryptoAdapter,
            encryptionKey: webKeys.encryptionKey,
          }),
          expiresAtUnixSeconds,
          pairingId,
          recipientNostrPubkey: mobileNostr.publicKey,
          secretKey: webNostr.secretKey,
        }),
      )
    }

    relaySet.publish(
      createKeywardenEvent({
        envelope: await encryptProtocolMessage({
          body: {
            header: makeHeader({
              pairingId,
              recipientNostrPubkey: webNostr.publicKey,
              senderNostrPubkey: mobileNostr.publicKey,
              sequence: mobileSequence++,
              type: 'pairing.confirmed',
            }),
          },
          cryptoAdapter,
          encryptionKey: mobileKeys.encryptionKey,
        }),
        expiresAtUnixSeconds,
        pairingId,
        recipientNostrPubkey: webNostr.publicKey,
        secretKey: mobileNostr.secretKey,
      }),
    )

    const records = [1, 2, 3].map((seedValue) =>
      fixtureRecord(seedValue, `record-${seedValue}`),
    )
    const transferId = bytesToBase64Url(cryptoAdapter.randomBytes(16))
    const bundle: TransferBundleV1 = {
      createdAt: new Date().toISOString(),
      records,
      schema: 'keywarden.transfer-bundle',
      transferId,
      version: 1,
    }
    const bundleBytes = serializeTransferBundleV1(bundle)
    const bundleSha256 = bytesToBase64Url(
      await cryptoAdapter.sha256(bundleBytes),
    )
    const chunks = createTransferChunks({
      bytes: bundleBytes,
      chunkPlaintextSize: 96,
      transferId,
    })
    const manifest = createTransferManifest({
      bundleByteLength: bundleBytes.byteLength,
      bundleSha256,
      chunkCount: chunks.length,
      chunkPlaintextSize: 96,
      recordCount: records.length,
      transferId,
    })

    expect(chunks.length).toBeGreaterThan(1)

    const transferBodies: KeywardenMessageBodyV1[] = [
      {
        header: makeHeader({
          pairingId,
          recipientNostrPubkey: mobileNostr.publicKey,
          senderNostrPubkey: webNostr.publicKey,
          sequence: webSequence++,
          type: 'transfer.manifest',
        }),
        manifest,
      },
      ...chunks.map(
        (chunk): KeywardenMessageBodyV1 => ({
          chunk,
          header: makeHeader({
            pairingId,
            recipientNostrPubkey: mobileNostr.publicKey,
            senderNostrPubkey: webNostr.publicKey,
            sequence: webSequence++,
            type: 'transfer.chunk',
          }),
        }),
      ),
    ]

    for (const body of transferBodies) {
      const published = relaySet.publish(
        createKeywardenEvent({
          envelope: await encryptProtocolMessage({
            body,
            cryptoAdapter,
            encryptionKey: webKeys.encryptionKey,
          }),
          expiresAtUnixSeconds,
          pairingId,
          recipientNostrPubkey: mobileNostr.publicKey,
          secretKey: webNostr.secretKey,
        }),
      )

      expect(published.acceptedBy).toEqual([relays[1]])
    }

    const mobileTracker = new DuplicateTracker()
    const receivedChunks = []
    let receivedManifest: typeof manifest | undefined

    for (const event of relaySet.deliver()) {
      if (getTagValue(event, 'p') !== mobileNostr.publicKey) {
        continue
      }

      const verified = validateKeywardenEvent({
        event,
        expectedPairingId: pairingId,
        expectedRecipientNostrPubkey: mobileNostr.publicKey,
      })

      if (!mobileTracker.accept(verified)) {
        continue
      }

      const message = await decryptProtocolMessage({
        cryptoAdapter,
        encryptionKey: mobileKeys.encryptionKey,
        envelope: parseKeywardenEventEnvelope(verified),
        pairingId,
        recipientNostrPubkey: mobileNostr.publicKey,
        senderNostrPubkey: webNostr.publicKey,
      })

      if ('manifest' in message) {
        receivedManifest = message.manifest
      }
      if ('chunk' in message) {
        receivedChunks.push(message.chunk)
      }
    }

    expect(receivedManifest).toBeDefined()
    expect(receivedManifest?.bundleSha256).toBe(bundleSha256)
    expect(receivedChunks).toHaveLength(chunks.length)

    const reassembledBytes = reassembleTransferChunks(receivedChunks)
    const manifestBundleByteLength = receivedManifest?.bundleByteLength
    const manifestBundleSha256 = receivedManifest?.bundleSha256
    if (
      manifestBundleByteLength === undefined ||
      manifestBundleSha256 === undefined
    ) {
      throw new Error('Missing transfer manifest')
    }

    expect(reassembledBytes.byteLength).toBe(manifestBundleByteLength)
    expect(bytesToBase64Url(await cryptoAdapter.sha256(reassembledBytes))).toBe(
      manifestBundleSha256,
    )

    const receivedBundle = TransferBundleV1Schema.parse(
      JSON.parse(new TextDecoder().decode(reassembledBytes)),
    )
    const repository = new InMemoryEncryptedSecretRepository()
    const { session } = await createVaultSession({
      cryptoAdapter,
      vaultKeyBytes: new Uint8Array(32).fill(9),
      vaultId: 'vault',
    })
    const imported = await importTransferBundle({
      bundle: receivedBundle,
      bundleSha256,
      cryptoAdapter,
      pairingId,
      repository,
      senderNostrPubkey: webNostr.publicKey,
      session,
    })

    expect(imported.ack.importedCount).toBe(3)
    expect(imported.ack.skippedCount).toBe(0)

    const retry = await importTransferBundle({
      bundle: receivedBundle,
      bundleSha256,
      cryptoAdapter,
      pairingId,
      repository,
      senderNostrPubkey: webNostr.publicKey,
      session,
    })

    expect(retry.ack.importedCount).toBe(0)
    expect(retry.ack.skippedCount).toBe(3)

    const rows = await repository.list('vault')
    expect(rows).toHaveLength(3)
    for (const row of rows) {
      expect(row.ciphertext).not.toContain(records[0]?.publicAddress ?? '')
      expect(row).not.toHaveProperty('publicAddress')
    }

    await expect(
      decryptVaultRows({ cryptoAdapter, rows, session }),
    ).resolves.toHaveLength(3)

    const ackBody: KeywardenMessageBodyV1 = {
      ack: imported.ack,
      header: makeHeader({
        pairingId,
        recipientNostrPubkey: webNostr.publicKey,
        senderNostrPubkey: mobileNostr.publicKey,
        sequence: mobileSequence++,
        type: 'transfer.ack',
      }),
    }
    const ackEvent = createKeywardenEvent({
      envelope: await encryptProtocolMessage({
        body: ackBody,
        cryptoAdapter,
        encryptionKey: mobileKeys.encryptionKey,
      }),
      expiresAtUnixSeconds,
      pairingId,
      recipientNostrPubkey: webNostr.publicKey,
      secretKey: mobileNostr.secretKey,
    })
    relaySet.publish(ackEvent)

    const verifiedAck = validateKeywardenEvent({
      event: ackEvent,
      expectedPairingId: pairingId,
      expectedRecipientNostrPubkey: webNostr.publicKey,
    })
    await expect(
      decryptProtocolMessage({
        cryptoAdapter,
        encryptionKey: webKeys.encryptionKey,
        envelope: parseKeywardenEventEnvelope(verifiedAck),
        pairingId,
        recipientNostrPubkey: webNostr.publicKey,
        senderNostrPubkey: mobileNostr.publicKey,
      }),
    ).resolves.toMatchObject({
      ack: {
        bundleSha256,
        importedCount: 3,
        skippedCount: 0,
        status: 'committed',
        transferId,
      },
    })
  })
})
