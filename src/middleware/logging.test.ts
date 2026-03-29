import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type { Request, Response } from 'express';

import { REDACTED_LOG_VALUE } from '../logger.js';
import { logger, requestLogger, structuredLoggerOptions } from './logging.js';

describe('structured logger options', () => {
  test('redaction hook masks sensitive structured fields before logging', () => {
    const method = jest.fn();

    structuredLoggerOptions.hooks?.logMethod?.call(
      {} as never,
      [
        {
          headers: {
            authorization: 'Bearer top-secret',
            'x-api-key': 'ck_live_secret',
          },
          password: 'super-secret',
          nested: {
            token: 'jwt-secret',
            ok: true,
          },
        },
      ],
      method,
      30,
    );

    assert.deepEqual(method.mock.calls[0], [
      {
        headers: {
          authorization: REDACTED_LOG_VALUE,
          'x-api-key': REDACTED_LOG_VALUE,
        },
        password: REDACTED_LOG_VALUE,
        nested: {
          token: REDACTED_LOG_VALUE,
          ok: true,
        },
      },
    ]);
  });
});

describe('requestLogger', () => {
  test('logs only safe request metadata and honors caller request id', () => {
    const infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => logger);

    try {
      const req = {
        headers: {
          authorization: 'Bearer secret-token',
          'x-api-key': 'ck_live_secret',
          'x-request-id': 'req-safe-1',
        },
        method: 'POST',
        path: '/api/vault/deposit/prepare',
      } as unknown as Request;

      const res = new EventEmitter() as EventEmitter &
        Response & {
          statusCode: number;
          setHeader: jest.Mock;
        };
      res.statusCode = 200;
      res.setHeader = jest.fn();

      const next = jest.fn();

      requestLogger(req, res, next);
      res.emit('finish');

      assert.equal(next.mock.calls.length, 1);
      assert.deepEqual(res.setHeader.mock.calls[0], ['x-request-id', 'req-safe-1']);
      assert.equal(infoSpy.mock.calls.length, 1);

      const [payload, message] = infoSpy.mock.calls[0] as [Record<string, unknown>, string];
      assert.equal(message, 'request completed');
      assert.equal(payload.requestId, 'req-safe-1');
      assert.equal(payload.method, 'POST');
      assert.equal(payload.path, '/api/vault/deposit/prepare');
      assert.equal(payload.statusCode, 200);
      assert.equal(typeof payload.durationMs, 'number');
      assert.equal('headers' in payload, false);
      assert.equal('body' in payload, false);
    } finally {
      infoSpy.mockRestore();
    }
  });

  test('uses error severity for 5xx responses', () => {
    const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => logger);

    try {
      const req = {
        headers: {},
        method: 'GET',
        path: '/api/health',
      } as unknown as Request;

      const res = new EventEmitter() as EventEmitter &
        Response & {
          statusCode: number;
          setHeader: jest.Mock;
        };
      res.statusCode = 503;
      res.setHeader = jest.fn();

      requestLogger(req, res, jest.fn());
      res.emit('finish');

      assert.equal(errorSpy.mock.calls.length, 1);
      const [payload, message] = errorSpy.mock.calls[0] as [Record<string, unknown>, string];
      assert.equal(message, 'request completed');
      assert.equal(payload.statusCode, 503);
    } finally {
      errorSpy.mockRestore();
    }
  });
});
