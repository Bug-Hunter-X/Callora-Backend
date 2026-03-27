import assert from 'node:assert/strict'
import type { Api } from '../db/schema.js'
import { InMemoryApiRepository } from './apiRepository.js'

const baseDate = new Date('2026-01-01T00:00:00.000Z')

const seedApis = (): Api[] => [
  {
    id: 1,
    developer_id: 10,
    name: 'Weather API',
    description: 'weather data',
    base_url: 'https://weather.example.com',
    logo_url: null,
    category: 'weather',
    status: 'active',
    created_at: baseDate,
    updated_at: baseDate,
  },
  {
    id: 2,
    developer_id: 10,
    name: 'Finance Draft',
    description: null,
    base_url: 'https://finance.example.com',
    logo_url: null,
    category: 'finance',
    status: 'draft',
    created_at: baseDate,
    updated_at: baseDate,
  },
  {
    id: 3,
    developer_id: 11,
    name: 'Maps API',
    description: null,
    base_url: 'https://maps.example.com',
    logo_url: null,
    category: 'maps',
    status: 'active',
    created_at: baseDate,
    updated_at: baseDate,
  },
]

test('create stores a new API with default draft status', async () => {
  const repository = new InMemoryApiRepository(seedApis())
  const created = await repository.create({
    developer_id: 10,
    name: 'Created API',
    base_url: 'https://created.example.com',
  })

  assert.equal(created.id, 4)
  assert.equal(created.status, 'draft')
  assert.equal(created.name, 'Created API')
})

test('update modifies an existing API and returns null when not found', async () => {
  const repository = new InMemoryApiRepository(seedApis())
  const updated = await repository.update(2, { status: 'active', name: 'Finance API' })
  assert.equal(updated?.status, 'active')
  assert.equal(updated?.name, 'Finance API')

  const missing = await repository.update(999, { name: 'Nope' })
  assert.equal(missing, null)
})

test('findById returns only active API details', async () => {
  const repository = new InMemoryApiRepository(seedApis())
  const active = await repository.findById(1)
  const draft = await repository.findById(2)
  const missing = await repository.findById(999)

  assert.equal(active?.id, 1)
  assert.equal(active?.status, 'active')
  assert.equal(draft, null)
  assert.equal(missing, null)
})

test('listByDeveloper supports status, category, search and pagination', async () => {
  const repository = new InMemoryApiRepository(seedApis())

  const byDeveloper = await repository.listByDeveloper(10)
  assert.equal(byDeveloper.length, 2)

  const byStatus = await repository.listByDeveloper(10, { status: 'draft' })
  assert.deepEqual(byStatus.map((a) => a.id), [2])

  const byCategory = await repository.listByDeveloper(10, { category: 'weather' })
  assert.deepEqual(byCategory.map((a) => a.id), [1])

  const bySearch = await repository.listByDeveloper(10, { search: 'finance' })
  assert.deepEqual(bySearch.map((a) => a.id), [2])

  const paginated = await repository.listByDeveloper(10, { offset: 1, limit: 1 })
  assert.deepEqual(paginated.map((a) => a.id), [2])
})

test('listPublic returns only active APIs with marketplace filters and pagination', async () => {
  const repository = new InMemoryApiRepository(seedApis())

  const allPublic = await repository.listPublic()
  assert.deepEqual(allPublic.map((a) => a.id), [1, 3])

  const filteredCategory = await repository.listPublic({ category: 'maps' })
  assert.deepEqual(filteredCategory.map((a) => a.id), [3])

  const filteredSearch = await repository.listPublic({ search: 'weather' })
  assert.deepEqual(filteredSearch.map((a) => a.id), [1])

  const paginated = await repository.listPublic({ offset: 1, limit: 1 })
  assert.deepEqual(paginated.map((a) => a.id), [3])

  const invalidStatus = await repository.listPublic({ status: 'draft' })
  assert.deepEqual(invalidStatus, [])
})

test('getEndpoints returns endpoint pricing data for billing', async () => {
  const repository = new InMemoryApiRepository(
    seedApis(),
    new Map([
      [
        1,
        [
          {
            path: '/v1/current',
            method: 'GET',
            price_per_call_usdc: '0.003',
            description: 'Current conditions',
          },
        ],
      ],
    ])
  )

  const endpoints = await repository.getEndpoints(1)
  assert.deepEqual(endpoints, [
    {
      path: '/v1/current',
      method: 'GET',
      price_per_call_usdc: '0.003',
      description: 'Current conditions',
    },
  ])
  const empty = await repository.getEndpoints(999)
  assert.deepEqual(empty, [])
})
