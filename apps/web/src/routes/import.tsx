import { createFileRoute } from '@tanstack/react-router'

import { KeywardenImportFeature } from '@/features/keywarden/feature/keywarden-import-feature'

export const Route = createFileRoute('/import')({
  component: KeywardenImportFeature,
})
