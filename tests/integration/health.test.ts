/**
 * Health Check Integration Tests
 *
 * Tests the health endpoint with real database integration via pg-mem.
 */

import assert from 'node:assert/strict';

import request from 'supertest';

jest.mock('uuid', () => ({ v4: () => 'mock-uuid-1234' }));

// Mock better-sqlite3 to prevent native binding errors on Windows
jest.mock('better-sqlite3', () => {
  return class MockDatabase {
    prepare() {
      return { get: () => null };
    }
    exec() {}
    close() {}
  };
});

import { createTestDb } from '../helpers/db.js';
import { createApp } from '../../src/app.js';
import type { HealthCheckConfig } from '../../src/services/healthCheck.js';

describe('GET /api/health - Integration Tests', () => {
  test('returns 200 with ok status when database is healthy', async () => {
    const testDb = createTestDb();

    try {
      const config: HealthCheckConfig = {
        version: '1.0.0',
        database: { pool: testDb.pool },
      };

      const app = createApp({ healthCheckConfig: config });
      const response = await request(app).get('/api/health');

      assert.equal(response.status, 200);
      assert.equal(response.body.status, 'ok');
      assert.equal(response.body.version, '1.0.0');
      assert.equal(response.body.checks.api, 'ok');
      assert.equal(response.body.checks.database, 'ok');
      assert.ok(response.body.timestamp);
    } finally {
      await testDb.end();
    }
  });

  test('returns 503 when database is down', async () => {
    const testDb = createTestDb();
    await testDb.end();

    // pg-mem doesn't always throw after end(), so force query failure.
    testDb.pool.query = async () => {
      throw new Error('Connection terminated');
    };

    const config: HealthCheckConfig = {
      version: '1.0.0',
      database: { pool: testDb.pool },
    };

    const app = createApp({ healthCheckConfig: config });
    const response = await request(app).get('/api/health');

    assert.equal(response.status, 503);
    assert.equal(response.body.status, 'down');
    assert.equal(response.body.checks.database, 'down');
  });

  test('returns 200 with degraded status when soroban rpc is unreachable', async () => {
    const testDb = createTestDb();

    try {
      const config: HealthCheckConfig = {
        version: '1.0.0',
        database: { pool: testDb.pool },
        sorobanRpc: {
          url: 'http://localhost:0',
          timeout: 200,
        },
      };

      const app = createApp({ healthCheckConfig: config });
      const response = await request(app).get('/api/health');

      assert.equal(response.status, 200);
      assert.equal(response.body.status, 'degraded');
      assert.equal(response.body.checks.database, 'ok');
      assert.equal(response.body.checks.soroban_rpc, 'down');
    } finally {
      await testDb.end();
    }
  });

  test('returns 200 with degraded status when horizon is unreachable', async () => {
    const testDb = createTestDb();

    try {
      const config: HealthCheckConfig = {
        version: '1.0.0',
        database: { pool: testDb.pool },
        horizon: {
          url: 'http://localhost:0',
          timeout: 200,
        },
      };

      const app = createApp({ healthCheckConfig: config });
      const response = await request(app).get('/api/health');

      assert.equal(response.status, 200);
      assert.equal(response.body.status, 'degraded');
      assert.equal(response.body.checks.database, 'ok');
      assert.equal(response.body.checks.horizon, 'down');
    } finally {
      await testDb.end();
    }
  });

  test('returns 200 when both optional deps fail but database is ok', async () => {
    const testDb = createTestDb();

    try {
      const config: HealthCheckConfig = {
        version: '1.0.0',
        database: { pool: testDb.pool },
        sorobanRpc: { url: 'http://localhost:0', timeout: 200 },
        horizon: { url: 'http://localhost:0', timeout: 200 },
      };

      const app = createApp({ healthCheckConfig: config });
      const response = await request(app).get('/api/health');

      assert.equal(response.status, 200);
      assert.equal(response.body.status, 'degraded');
      assert.equal(response.body.checks.database, 'ok');
      assert.equal(response.body.checks.soroban_rpc, 'down');
      assert.equal(response.body.checks.horizon, 'down');
    } finally {
      await testDb.end();
    }
  });

  test('returns simple health check when no config is provided', async () => {
    const app = createApp();
    const response = await request(app).get('/api/health');

    assert.equal(response.status, 200);
    assert.equal(response.body.status, 'ok');
    assert.equal(response.body.service, 'callora-backend');
  });

  test('does not expose sensitive error details in response body', async () => {
    const badPool = {
      query: async () => {
        throw new Error('Internal database error with sensitive info');
      },
    };

    const config: HealthCheckConfig = {
      database: { pool: badPool as any },
    };

    const app = createApp({ healthCheckConfig: config });
    const response = await request(app).get('/api/health');

    assert.equal(response.status, 503);
    assert.equal(response.body.status, 'down');
    assert.ok(!JSON.stringify(response.body).includes('sensitive info'));
  });

  test('completes health check within performance threshold', async () => {
    const testDb = createTestDb();

    try {
      const config: HealthCheckConfig = {
        database: { pool: testDb.pool, timeout: 500 },
      };

      const app = createApp({ healthCheckConfig: config });
      const startTime = Date.now();
      const response = await request(app).get('/api/health');
      const duration = Date.now() - startTime;

      assert.equal(response.status, 200);
      assert.ok(duration < 500, `Health check took ${duration}ms, expected < 500ms`);
    } finally {
      await testDb.end();
    }
  });
});
