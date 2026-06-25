import { utf8ToBytes } from './encoding'
import type { KeywardenAadV1, PairingKeyInfoV1 } from './types'

type JsonValue =
  | boolean
  | number
  | string
  | null
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue | undefined }

export function stableJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value)
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(',')}]`
  }

  const entries = Object.entries(value)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right))

  return `{${entries
    .map(
      ([key, entryValue]) =>
        `${JSON.stringify(key)}:${stableJson(entryValue as JsonValue)}`,
    )
    .join(',')}}`
}

export function stableUtf8Json(value: JsonValue): Uint8Array {
  return utf8ToBytes(stableJson(value))
}

export function stringifyAad(aad: KeywardenAadV1): string {
  const entries: Array<[string, JsonValue | undefined]> = [
    ['protocol', aad.protocol],
    ['version', aad.version],
    ['pairingId', aad.pairingId],
    ['messageId', aad.messageId],
    ['sequence', aad.sequence],
    ['senderNostrPubkey', aad.senderNostrPubkey],
    ['recipientNostrPubkey', aad.recipientNostrPubkey],
    ['senderEcdhPublicKey', aad.senderEcdhPublicKey],
  ]

  return `{${entries
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value)}`)
    .join(',')}}`
}

export function stringifyPairingKeyInfo(info: PairingKeyInfoV1): string {
  const entries: Array<[keyof PairingKeyInfoV1, JsonValue]> = [
    ['protocol', info.protocol],
    ['version', info.version],
    ['purpose', info.purpose],
    ['pairingId', info.pairingId],
    ['webNostrPubkey', info.webNostrPubkey],
    ['mobileNostrPubkey', info.mobileNostrPubkey],
    ['webEcdhPublicKey', info.webEcdhPublicKey],
    ['mobileEcdhPublicKey', info.mobileEcdhPublicKey],
  ]

  return `{${entries
    .map(([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value)}`)
    .join(',')}}`
}
