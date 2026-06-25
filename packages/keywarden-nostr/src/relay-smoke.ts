import { bytesToBase64Url } from '@keywarden/core'

import {
  createKeywardenEvent,
  createKeywardenNostrKeypair,
  createKeywardenSubscriptionFilter,
  KeywardenRelayTransport,
  validateKeywardenEvent,
} from './index'

const relays = process.argv.slice(2)
if (relays.length === 0) {
  relays.push('wss://relay.damus.io', 'wss://nos.lol')
}

const transport = new KeywardenRelayTransport()
const keypair = createKeywardenNostrKeypair()
const pairingId = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(16)))
const expiresAtUnixSeconds = Math.floor(Date.now() / 1000) + 60
const event = createKeywardenEvent({
  envelope: {
    ciphertext: bytesToBase64Url(new TextEncoder().encode('smoke-test')),
    messageId: crypto.randomUUID(),
    nonce: bytesToBase64Url(crypto.getRandomValues(new Uint8Array(12))),
    sequence: 0,
    version: 1,
  },
  expiresAtUnixSeconds,
  pairingId,
  recipientNostrPubkey: keypair.publicKey,
  secretKey: keypair.secretKey,
})

await transport.connect(relays)
const capabilities = await transport.fetchCapabilities(relays)
const published = await transport.publish(relays, event)

console.info(
  JSON.stringify(
    {
      capabilities,
      eventId: event.id,
      published,
      relays,
    },
    null,
    2,
  ),
)

await new Promise<void>((resolve) => {
  const timeout = setTimeout(resolve, 5000)
  const subscription = transport.subscribe({
    filter: createKeywardenSubscriptionFilter({
      pairingId,
      receiverNostrPubkey: keypair.publicKey,
      sessionExpiresAtUnixSeconds: expiresAtUnixSeconds,
      sessionStartedAtUnixSeconds: Math.floor(Date.now() / 1000) - 5,
    }),
    onEvent: (received, relay) => {
      if (received.id === event.id) {
        validateKeywardenEvent({
          event: received,
          expectedPairingId: pairingId,
          expectedRecipientNostrPubkey: keypair.publicKey,
        })
        console.info(JSON.stringify({ relay, returned: received.id }))
        clearTimeout(timeout)
        subscription.close()
        resolve()
      }
    },
    relays,
  })
})

transport.close()
