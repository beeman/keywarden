import { describe, expect, test } from 'bun:test'
import { createECDH } from 'node:crypto'

import {
  createWebCryptoAdapter,
  deriveVerificationCode,
  runCryptoCapabilitySmokeTest,
} from '../src'

describe('@keywarden/crypto', () => {
  test('runs the required Web Crypto smoke test', async () => {
    await expect(
      runCryptoCapabilitySmokeTest(createWebCryptoAdapter(globalThis.crypto)),
    ).resolves.toBeUndefined()
  })

  test('derives matching pairing keys and verification codes', async () => {
    const cryptoAdapter = createWebCryptoAdapter(globalThis.crypto)
    const web = await cryptoAdapter.generateEcdhKeyPair()
    const mobile = await cryptoAdapter.generateEcdhKeyPair()
    const webPublic = await cryptoAdapter.exportEcdhPublicKey(web.publicKey)
    const mobilePublic = await cryptoAdapter.exportEcdhPublicKey(
      mobile.publicKey,
    )
    const pairingSecret = new Uint8Array(32).fill(7)
    const webKeys = await cryptoAdapter.derivePairingKeys({
      mobileEcdhPublicKey: mobilePublic,
      mobileNostrPubkey: 'b'.repeat(64),
      ownPrivateKey: web.privateKey,
      pairingId: 'pairing',
      pairingSecret,
      peerPublicKey: await cryptoAdapter.importEcdhPublicKey(mobilePublic),
      webEcdhPublicKey: webPublic,
      webNostrPubkey: 'a'.repeat(64),
    })
    const mobileKeys = await cryptoAdapter.derivePairingKeys({
      mobileEcdhPublicKey: mobilePublic,
      mobileNostrPubkey: 'b'.repeat(64),
      ownPrivateKey: mobile.privateKey,
      pairingId: 'pairing',
      pairingSecret,
      peerPublicKey: await cryptoAdapter.importEcdhPublicKey(webPublic),
      webEcdhPublicKey: webPublic,
      webNostrPubkey: 'a'.repeat(64),
    })

    await expect(
      deriveVerificationCode(cryptoAdapter, webKeys.verificationKey),
    ).resolves.toBe(
      await deriveVerificationCode(cryptoAdapter, mobileKeys.verificationKey),
    )
  })

  test('falls back to native ECDH when the runtime rejects the P-256 alias', async () => {
    const cryptoAdapter = createWebCryptoAdapter(
      createP256AliasFailureRuntime(),
    )
    const web = await cryptoAdapter.generateEcdhKeyPair()
    const mobile = await cryptoAdapter.generateEcdhKeyPair()
    const webPublic = await cryptoAdapter.exportEcdhPublicKey(web.publicKey)
    const mobilePublic = await cryptoAdapter.exportEcdhPublicKey(
      mobile.publicKey,
    )
    const pairingSecret = new Uint8Array(32).fill(11)
    const webKeys = await cryptoAdapter.derivePairingKeys({
      mobileEcdhPublicKey: mobilePublic,
      mobileNostrPubkey: 'd'.repeat(64),
      ownPrivateKey: web.privateKey,
      pairingId: 'fallback-pairing',
      pairingSecret,
      peerPublicKey: await cryptoAdapter.importEcdhPublicKey(mobilePublic),
      webEcdhPublicKey: webPublic,
      webNostrPubkey: 'c'.repeat(64),
    })
    const mobileKeys = await cryptoAdapter.derivePairingKeys({
      mobileEcdhPublicKey: mobilePublic,
      mobileNostrPubkey: 'd'.repeat(64),
      ownPrivateKey: mobile.privateKey,
      pairingId: 'fallback-pairing',
      pairingSecret,
      peerPublicKey: await cryptoAdapter.importEcdhPublicKey(webPublic),
      webEcdhPublicKey: webPublic,
      webNostrPubkey: 'c'.repeat(64),
    })

    await expect(
      deriveVerificationCode(cryptoAdapter, webKeys.verificationKey),
    ).resolves.toBe(
      await deriveVerificationCode(cryptoAdapter, mobileKeys.verificationKey),
    )
  })
})

function createP256AliasFailureRuntime(): Crypto {
  const subtle = new Proxy(globalThis.crypto.subtle, {
    get(target, property, receiver) {
      if (property === 'deriveBits') {
        return async (
          algorithm: EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params,
          baseKey: CryptoKey,
          length: number,
        ) => {
          if (algorithm.name === 'ECDH') {
            throw new Error('ECDH.init(...): ECDH: unknown curve name: P-256')
          }
          return target.deriveBits(algorithm, baseKey, length)
        }
      }

      const value = Reflect.get(target, property, receiver)
      return typeof value === 'function' ? value.bind(target) : value
    },
  }) as SubtleCrypto

  return {
    createECDH,
    getRandomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto),
    subtle,
  } as unknown as Crypto
}
