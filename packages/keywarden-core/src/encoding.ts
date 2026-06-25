const decoder = new TextDecoder()
const encoder = new TextEncoder()

export function base64UrlToBytes(value: string): Uint8Array {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/')
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')

  if (typeof atob === 'function') {
    return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0))
  }

  return Uint8Array.from(Buffer.from(padded, 'base64'))
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let base64: string

  if (typeof btoa === 'function') {
    let binary = ''
    for (let index = 0; index < bytes.length; index += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000))
    }
    base64 = btoa(binary)
  } else {
    base64 = Buffer.from(bytes).toString('base64')
  }

  return base64.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  )
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes)
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0)
  const output = new Uint8Array(length)
  let offset = 0

  for (const part of parts) {
    output.set(part, offset)
    offset += part.byteLength
  }

  return output
}

export function encodeLengthPrefixed(parts: readonly Uint8Array[]): Uint8Array {
  const encoded = parts.map((part) => {
    const length = new Uint8Array(4)
    new DataView(length.buffer).setUint32(0, part.byteLength, false)
    return concatBytes([length, part])
  })

  return concatBytes(encoded)
}

export function hexToBytes(value: string): Uint8Array {
  if (!/^[\da-f]*$/u.test(value) || value.length % 2 !== 0) {
    throw new Error('Invalid lowercase hex value')
  }

  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < value.length; index += 2) {
    bytes[index / 2] = Number.parseInt(value.slice(index, index + 2), 16)
  }
  return bytes
}

export function utf8ToBytes(value: string): Uint8Array {
  return encoder.encode(value)
}

export function zeroBytes(bytes: Uint8Array): void {
  bytes.fill(0)
}
