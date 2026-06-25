import { useLocalSearchParams } from 'expo-router'
import { HomeFeatureIndex } from '@/features/home/feature/home-feature-index'

export default function PairingRoute() {
  const { data } = useLocalSearchParams<{ data?: string }>()
  const pairingData = typeof data === 'string' ? data : null

  return (
    <HomeFeatureIndex
      initialPairingUri={
        pairingData
          ? `keywarden:/v1/pair?data=${encodeURIComponent(pairingData)}`
          : undefined
      }
    />
  )
}
