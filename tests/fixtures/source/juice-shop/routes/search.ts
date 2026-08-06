export interface SyntheticSearchResult {
  id: number
  label: string
}

const catalog: SyntheticSearchResult[] = [
  { id: 1, label: 'sample' }
]

export function searchCatalog (query: string): SyntheticSearchResult[] {
  const normalized = query.trim().toLowerCase()
  return catalog.filter((item) => item.label.includes(normalized))
}

export function firstResult (query: string): SyntheticSearchResult | null {
  const results = searchCatalog(query)
  return results.length > 0 ? results[0] : null
}
