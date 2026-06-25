import type { Event, Filter } from 'nostr-tools'
import { fetchRelayInformation } from 'nostr-tools/nip11'
import { SimplePool } from 'nostr-tools/pool'

export type KeywardenRelayPublishResult = {
  acceptedBy: string[]
  rejectedBy: Array<{
    reason: string
    relay: string
  }>
}

export type KeywardenRelaySubscription = {
  close(): void
}

export class KeywardenRelayTransport {
  private pool = new SimplePool()

  async connect(relays: readonly string[]): Promise<void> {
    await Promise.allSettled(
      relays.map((relay) =>
        this.pool.ensureRelay(relay, { connectionTimeout: 3000 }),
      ),
    )
  }

  async fetchCapabilities(relays: readonly string[]): Promise<
    Array<{
      maxContentLength?: number
      relay: string
    }>
  > {
    const results = await Promise.allSettled(
      relays.map(async (relay) => {
        const info = await fetchRelayInformation(relay)
        return {
          maxContentLength: info.limitation?.max_content_length,
          relay,
        }
      }),
    )

    return results.map((result, index) => {
      const relay = relays[index] ?? ''
      if (result.status === 'fulfilled') {
        return result.value
      }
      return { relay }
    })
  }

  async publish(
    relays: readonly string[],
    event: Event,
  ): Promise<KeywardenRelayPublishResult> {
    const settled = await Promise.allSettled(
      this.pool.publish([...relays], event),
    )
    const acceptedBy: string[] = []
    const rejectedBy: KeywardenRelayPublishResult['rejectedBy'] = []

    for (const [index, result] of settled.entries()) {
      const relay = relays[index] ?? 'unknown'
      if (result.status === 'fulfilled') {
        const reason = String(result.value)
        if (reason.startsWith('connection failure:')) {
          rejectedBy.push({
            reason: sanitizeRelayReason(reason),
            relay,
          })
        } else {
          acceptedBy.push(relay)
        }
      } else {
        rejectedBy.push({
          reason: sanitizeRelayReason(result.reason),
          relay,
        })
      }
    }

    return {
      acceptedBy,
      rejectedBy,
    }
  }

  subscribe(input: {
    filter: Filter
    onEose?: (relay: string) => void
    onEvent: (event: Event, relay: string) => void
    relays: readonly string[]
  }): KeywardenRelaySubscription {
    const closer = this.pool.subscribeMany([...input.relays], input.filter, {
      oneose: () => {
        for (const relay of input.relays) {
          input.onEose?.(relay)
        }
      },
      onevent: (event) => {
        const seenOn = this.pool.seenOn.get(event.id)
        const relay = seenOn ? [...seenOn][0]?.url : undefined
        input.onEvent(event, relay ?? 'unknown')
      },
    })

    return {
      close: () => closer.close('keywarden-session-closed'),
    }
  }

  close(): void {
    this.pool.destroy()
  }
}

function sanitizeRelayReason(reason: unknown): string {
  if (reason instanceof Error) {
    return reason.message.slice(0, 160)
  }
  return String(reason).slice(0, 160)
}
