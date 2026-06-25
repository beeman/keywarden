import { KeywardenVaultFeature } from '@/features/keywarden/feature/keywarden-vault-feature'

type HomeFeatureIndexProps = {
  initialPairingUri?: string
}

export function HomeFeatureIndex({ initialPairingUri }: HomeFeatureIndexProps) {
  return <KeywardenVaultFeature initialPairingUri={initialPairingUri} />
}
