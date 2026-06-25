export interface KeywardenCrypto {
  decrypt(input: {
    aad: Uint8Array
    ciphertext: Uint8Array
    key: CryptoKey
    nonce: Uint8Array
  }): Promise<Uint8Array>

  derivePairingKeys(input: {
    mobileEcdhPublicKey: Uint8Array
    mobileNostrPubkey: string
    ownPrivateKey: CryptoKey
    pairingId: string
    pairingSecret: Uint8Array
    peerPublicKey: CryptoKey
    webEcdhPublicKey: Uint8Array
    webNostrPubkey: string
  }): Promise<{
    encryptionKey: CryptoKey
    verificationKey: CryptoKey
  }>

  deriveRecordKey(input: {
    recordId: string
    vaultKey: CryptoKey
  }): Promise<CryptoKey>

  encrypt(input: {
    aad: Uint8Array
    key: CryptoKey
    plaintext: Uint8Array
  }): Promise<{
    ciphertext: Uint8Array
    nonce: Uint8Array
  }>

  exportEcdhPublicKey(publicKey: CryptoKey): Promise<Uint8Array>

  generateEcdhKeyPair(): Promise<CryptoKeyPair>

  hmacSha256(key: CryptoKey, input: Uint8Array): Promise<Uint8Array>

  importEcdhPublicKey(raw: Uint8Array): Promise<CryptoKey>

  importHmacKey(raw: Uint8Array): Promise<CryptoKey>

  importVaultEncryptionKey(raw: Uint8Array): Promise<CryptoKey>

  randomBytes(length: number): Uint8Array

  sha256(input: Uint8Array): Promise<Uint8Array>
}
