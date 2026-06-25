import {
  base64UrlToBytes,
  bytesToBase64Url,
  encodeLengthPrefixed,
  stringifyPairingKeyInfo,
  utf8ToBytes,
  zeroBytes,
} from '@keywarden/core'

import type { KeywardenCrypto } from './types'

const AES_GCM_NONCE_BYTES = 12

type DerivePairingKeysInput = Parameters<
  KeywardenCrypto['derivePairingKeys']
>[0]

type NodeEcdh = {
  computeSecret(
    publicKey: string,
    inputEncoding: 'hex',
  ): ArrayBuffer | ArrayBufferView
  setPrivateKey(privateKey: string, encoding: 'hex'): void
}

type P256PrivateJwk = {
  d?: string
  x?: string
  y?: string
}

type RuntimeCryptoWithNodeEcdh = Crypto & {
  createECDH?: (curveName: string) => NodeEcdh
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false
  }

  let difference = 0
  for (let index = 0; index < left.byteLength; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0)
  }
  return difference === 0
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

function copyBufferBytes(input: ArrayBuffer | ArrayBufferView): Uint8Array {
  const view =
    input instanceof ArrayBuffer
      ? new Uint8Array(input)
      : new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
  const copy = new Uint8Array(view.byteLength)
  copy.set(view)
  return copy
}

function toUint8Array(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer)
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

function extractRawP256PublicKeyFromSpki(spki: Uint8Array): Uint8Array {
  const publicPoint = spki.slice(-65)
  if (publicPoint.byteLength !== 65 || publicPoint[0] !== 0x04) {
    throw new Error('CRYPTO_UNAVAILABLE')
  }
  return publicPoint
}

async function deriveP256SharedSecretWithNodeEcdh(
  runtimeCrypto: Crypto,
  subtle: SubtleCrypto,
  input: DerivePairingKeysInput,
  webCryptoCause: unknown,
): Promise<Uint8Array> {
  const createECDH = (runtimeCrypto as RuntimeCryptoWithNodeEcdh).createECDH
  if (!createECDH) {
    if (webCryptoCause instanceof Error) {
      throw webCryptoCause
    }
    throw new Error('Native ECDH fallback is unavailable')
  }

  const privateJwk = (await subtle.exportKey(
    'jwk',
    input.ownPrivateKey,
  )) as P256PrivateJwk
  const privateKey = p256PrivateKeyFromJwk(privateJwk)

  try {
    const ecdh = createECDH('prime256v1')
    const ownPublicKey = rawP256PublicKeyFromJwk(privateJwk)
    const peerPublicKey = selectPeerP256PublicKey(input, ownPublicKey)

    ecdh.setPrivateKey(bytesToHex(privateKey), 'hex')
    const sharedSecret = copyBufferBytes(
      ecdh.computeSecret(bytesToHex(peerPublicKey), 'hex'),
    )

    if (sharedSecret.byteLength !== 32) {
      throw new Error('Native ECDH returned an invalid shared-secret length')
    }

    return sharedSecret
  } finally {
    zeroBytes(privateKey)
  }
}

function isCryptoError(cause: unknown): cause is Error {
  return cause instanceof Error && cause.message.startsWith('CRYPTO_')
}

function createCryptoError(code: string, cause: unknown): Error {
  if (!(cause instanceof Error) || !cause.message) {
    return new Error(code)
  }
  return new Error(`${code}: ${cause.message}`)
}

function p256PrivateKeyFromJwk(jwk: P256PrivateJwk): Uint8Array {
  if (!jwk.d) {
    throw new Error('ECDH private JWK is missing private key material')
  }
  const privateKey = base64UrlToBytes(jwk.d)
  if (privateKey.byteLength !== 32) {
    throw new Error('ECDH private JWK has invalid private key length')
  }
  return privateKey
}

function rawP256PublicKeyFromJwk(jwk: P256PrivateJwk): Uint8Array {
  if (!jwk.x || !jwk.y) {
    throw new Error('ECDH private JWK is missing public coordinates')
  }

  const x = base64UrlToBytes(jwk.x)
  const y = base64UrlToBytes(jwk.y)
  if (x.byteLength !== 32 || y.byteLength !== 32) {
    throw new Error('ECDH private JWK has invalid public coordinate length')
  }

  const publicKey = new Uint8Array(65)
  publicKey[0] = 0x04
  publicKey.set(x, 1)
  publicKey.set(y, 33)
  return publicKey
}

async function runCryptoAdapterStep<T>(
  code: string,
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation()
  } catch (cause) {
    if (isCryptoError(cause)) {
      throw cause
    }
    throw createCryptoError(code, cause)
  }
}

function selectPeerP256PublicKey(
  input: DerivePairingKeysInput,
  ownPublicKey: Uint8Array,
): Uint8Array {
  if (bytesEqual(ownPublicKey, input.mobileEcdhPublicKey)) {
    return input.webEcdhPublicKey
  }
  if (bytesEqual(ownPublicKey, input.webEcdhPublicKey)) {
    return input.mobileEcdhPublicKey
  }

  throw new Error('ECDH private key does not match the pairing transcript')
}

export function createWebCryptoAdapter(runtimeCrypto: Crypto): KeywardenCrypto {
  const subtle = runtimeCrypto.subtle

  if (!runtimeCrypto.getRandomValues || !subtle) {
    throw new Error('CRYPTO_UNAVAILABLE')
  }

  return {
    async decrypt(input) {
      const plaintext = await subtle.decrypt(
        {
          additionalData: toArrayBuffer(input.aad),
          iv: toArrayBuffer(input.nonce),
          name: 'AES-GCM',
        },
        input.key,
        toArrayBuffer(input.ciphertext),
      )

      return toUint8Array(plaintext)
    },

    async derivePairingKeys(input) {
      const sharedSecret = await runCryptoAdapterStep(
        'CRYPTO_ECDH_DERIVE_FAILED',
        async () => {
          try {
            return toUint8Array(
              await subtle.deriveBits(
                {
                  name: 'ECDH',
                  public: input.peerPublicKey,
                },
                input.ownPrivateKey,
                256,
              ),
            )
          } catch (cause) {
            // react-native-quick-crypto's WebCrypto ECDH wrapper passes
            // "P-256" into native ECDH, while its native API accepts the
            // OpenSSL alias "prime256v1".
            return deriveP256SharedSecretWithNodeEcdh(
              runtimeCrypto,
              subtle,
              input,
              cause,
            )
          }
        },
      )

      const saltInput = encodeLengthPrefixed([
        utf8ToBytes('keywarden/pairing/salt/v1'),
        input.pairingSecret,
        utf8ToBytes(input.pairingId),
      ])
      const salt = await runCryptoAdapterStep(
        'CRYPTO_PAIRING_SALT_FAILED',
        async () =>
          toUint8Array(
            await subtle.digest('SHA-256', toArrayBuffer(saltInput)),
          ),
      )
      const info = utf8ToBytes(
        stringifyPairingKeyInfo({
          mobileEcdhPublicKey: bytesToBase64Url(input.mobileEcdhPublicKey),
          mobileNostrPubkey: input.mobileNostrPubkey,
          pairingId: input.pairingId,
          protocol: 'keywarden',
          purpose: 'pairing-key-material',
          version: 1,
          webEcdhPublicKey: bytesToBase64Url(input.webEcdhPublicKey),
          webNostrPubkey: input.webNostrPubkey,
        }),
      )
      const hkdfKey = await runCryptoAdapterStep(
        'CRYPTO_HKDF_IMPORT_FAILED',
        () =>
          subtle.importKey('raw', toArrayBuffer(sharedSecret), 'HKDF', false, [
            'deriveBits',
          ]),
      )
      const keyMaterial = await runCryptoAdapterStep(
        'CRYPTO_HKDF_DERIVE_FAILED',
        async () =>
          toUint8Array(
            await subtle.deriveBits(
              {
                hash: 'SHA-256',
                info: toArrayBuffer(info),
                name: 'HKDF',
                salt: toArrayBuffer(salt),
              },
              hkdfKey,
              512,
            ),
          ),
      )
      const encryptionKeyBytes = keyMaterial.slice(0, 32)
      const verificationKeyBytes = keyMaterial.slice(32)
      const encryptionKey = await runCryptoAdapterStep(
        'CRYPTO_PAIRING_AES_IMPORT_FAILED',
        () =>
          subtle.importKey(
            'raw',
            toArrayBuffer(encryptionKeyBytes),
            { name: 'AES-GCM' },
            false,
            ['decrypt', 'encrypt'],
          ),
      )
      const verificationKey = await runCryptoAdapterStep(
        'CRYPTO_PAIRING_HMAC_IMPORT_FAILED',
        () =>
          subtle.importKey(
            'raw',
            toArrayBuffer(verificationKeyBytes),
            {
              hash: 'SHA-256',
              name: 'HMAC',
            },
            false,
            ['sign', 'verify'],
          ),
      )

      zeroBytes(sharedSecret)
      zeroBytes(keyMaterial)
      zeroBytes(encryptionKeyBytes)
      zeroBytes(verificationKeyBytes)

      return {
        encryptionKey,
        verificationKey,
      }
    },

    async deriveRecordKey(input) {
      const recordIdBytes = utf8ToBytes(input.recordId)
      const salt = toUint8Array(
        await subtle.digest('SHA-256', toArrayBuffer(recordIdBytes)),
      )

      return subtle.deriveKey(
        {
          hash: 'SHA-256',
          info: toArrayBuffer(utf8ToBytes('keywarden/record/v1')),
          name: 'HKDF',
          salt: toArrayBuffer(salt),
        },
        input.vaultKey,
        {
          length: 256,
          name: 'AES-GCM',
        },
        false,
        ['decrypt', 'encrypt'],
      )
    },

    async encrypt(input) {
      const nonce = runtimeCrypto.getRandomValues(
        new Uint8Array(AES_GCM_NONCE_BYTES),
      )
      const ciphertext = await subtle.encrypt(
        {
          additionalData: toArrayBuffer(input.aad),
          iv: toArrayBuffer(nonce),
          name: 'AES-GCM',
        },
        input.key,
        toArrayBuffer(input.plaintext),
      )

      return {
        ciphertext: toUint8Array(ciphertext),
        nonce,
      }
    },

    async exportEcdhPublicKey(publicKey) {
      try {
        return toUint8Array(await subtle.exportKey('raw', publicKey))
      } catch {
        return extractRawP256PublicKeyFromSpki(
          toUint8Array(await subtle.exportKey('spki', publicKey)),
        )
      }
    },

    async generateEcdhKeyPair() {
      return subtle.generateKey(
        {
          namedCurve: 'P-256',
          name: 'ECDH',
        },
        true,
        ['deriveBits'],
      )
    },

    async hmacSha256(key, input) {
      return toUint8Array(await subtle.sign('HMAC', key, toArrayBuffer(input)))
    },

    async importEcdhPublicKey(raw) {
      return subtle.importKey(
        'raw',
        toArrayBuffer(raw),
        {
          namedCurve: 'P-256',
          name: 'ECDH',
        },
        false,
        [],
      )
    },

    async importHmacKey(raw) {
      return subtle.importKey(
        'raw',
        toArrayBuffer(raw),
        {
          hash: 'SHA-256',
          name: 'HMAC',
        },
        false,
        ['sign', 'verify'],
      )
    },

    async importVaultEncryptionKey(raw) {
      return subtle.importKey('raw', toArrayBuffer(raw), 'HKDF', false, [
        'deriveKey',
      ])
    },

    randomBytes(length) {
      return runtimeCrypto.getRandomValues(new Uint8Array(length))
    },

    async sha256(input) {
      return toUint8Array(await subtle.digest('SHA-256', toArrayBuffer(input)))
    },
  }
}

export async function runCryptoCapabilitySmokeTest(
  cryptoAdapter: KeywardenCrypto,
): Promise<void> {
  const firstKeyPair = await runCryptoSmokeStep(
    'CRYPTO_ECDH_GENERATE_FAILED',
    () => cryptoAdapter.generateEcdhKeyPair(),
  )
  const secondKeyPair = await runCryptoSmokeStep(
    'CRYPTO_ECDH_GENERATE_FAILED',
    () => cryptoAdapter.generateEcdhKeyPair(),
  )
  const firstPublicKey = await runCryptoSmokeStep(
    'CRYPTO_ECDH_EXPORT_FAILED',
    () => cryptoAdapter.exportEcdhPublicKey(firstKeyPair.publicKey),
  )
  const secondPublicKey = await runCryptoSmokeStep(
    'CRYPTO_ECDH_EXPORT_FAILED',
    () => cryptoAdapter.exportEcdhPublicKey(secondKeyPair.publicKey),
  )
  const pairingSecret = cryptoAdapter.randomBytes(32)
  const importedSecondPublicKey = await runCryptoSmokeStep(
    'CRYPTO_ECDH_IMPORT_FAILED',
    () => cryptoAdapter.importEcdhPublicKey(secondPublicKey),
  )
  const keys = await runCryptoSmokeStep('CRYPTO_PAIRING_DERIVE_FAILED', () =>
    cryptoAdapter.derivePairingKeys({
      mobileEcdhPublicKey: secondPublicKey,
      mobileNostrPubkey: 'b'.repeat(64),
      ownPrivateKey: firstKeyPair.privateKey,
      pairingId: bytesToBase64Url(cryptoAdapter.randomBytes(16)),
      pairingSecret,
      peerPublicKey: importedSecondPublicKey,
      webEcdhPublicKey: firstPublicKey,
      webNostrPubkey: 'a'.repeat(64),
    }),
  )
  const aad = utf8ToBytes('capability-test')
  const plaintext = utf8ToBytes('keywarden')
  const encrypted = await runCryptoSmokeStep('CRYPTO_AES_GCM_FAILED', () =>
    cryptoAdapter.encrypt({
      aad,
      key: keys.encryptionKey,
      plaintext,
    }),
  )
  const decrypted = await runCryptoSmokeStep('CRYPTO_AES_GCM_FAILED', () =>
    cryptoAdapter.decrypt({
      aad,
      ciphertext: encrypted.ciphertext,
      key: keys.encryptionKey,
      nonce: encrypted.nonce,
    }),
  )
  const digest = await runCryptoSmokeStep('CRYPTO_SHA256_FAILED', () =>
    cryptoAdapter.sha256(plaintext),
  )
  const hmacKey = await runCryptoSmokeStep('CRYPTO_HMAC_IMPORT_FAILED', () =>
    cryptoAdapter.importHmacKey(base64UrlToBytes(bytesToBase64Url(digest))),
  )
  await runCryptoSmokeStep('CRYPTO_HMAC_FAILED', () =>
    cryptoAdapter.hmacSha256(hmacKey, plaintext),
  )

  if (new TextDecoder().decode(decrypted) !== 'keywarden') {
    throw new Error('CRYPTO_UNAVAILABLE')
  }
}

async function runCryptoSmokeStep<T>(
  code: string,
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation()
  } catch (cause) {
    if (isCryptoError(cause)) {
      throw cause
    }
    throw createCryptoError(code, cause)
  }
}
