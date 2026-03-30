import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { GatewayDeps } from '../types/gateway.js';
import { startUpstreamTimer } from '../metrics.js';
import { validate } from '../middleware/validate.js';
import { UnauthorizedError, PaymentRequiredError, TooManyRequestsError } from '../errors/index.js';

const CREDIT_COST_PER_CALL = 1; // cost per proxied request

/**
 * Factory that creates the gateway router with injected dependencies.
 * This makes the router fully testable with mocked services.
 */
export function createGatewayRouter(deps: GatewayDeps): Router {
  const { billing, rateLimiter, usageStore, upstreamUrl, apiKeys } = deps;
  const router = Router();

  // Validation schema for API ID parameter
  const apiIdParamsSchema = z.object({
    apiId: z.string().min(1, 'API ID is required').max(50, 'API ID too long')
  });

  /**
   * POST /api/gateway/:apiId
   *
   * Proxy flow:
   *   1. Validate API key from x-api-key header
   *   2. Rate-limit check
   *   3. Billing deduction (Soroban)
   *   4. Proxy request to upstream
   *   5. Record usage event
   *   6. Return upstream response
   */
  router.all('/:apiId', 
    validate({ params: apiIdParamsSchema }), 
    async (req: Request, res: Response, next: NextFunction) => {
      // 1. Validate API key
      const apiKeyHeader = req.headers['x-api-key'] as string | undefined;
      if (!apiKeyHeader) {
        return next(new UnauthorizedError('Unauthorized: missing x-api-key header'));
      }

      const keyRecord = apiKeys.get(apiKeyHeader);
      if (!keyRecord || keyRecord.apiId !== req.params.apiId) {
        return next(new UnauthorizedError('Unauthorized: invalid API key'));
      }

    // 2. Rate-limit check
    const rateResult = rateLimiter.check(apiKeyHeader);
    if (!rateResult.allowed) {
      const retryAfterSec = Math.ceil((rateResult.retryAfterMs ?? 1000) / 1000);
      res.set('Retry-After', String(retryAfterSec));
      const error = new TooManyRequestsError('Too Many Requests');
      return next(error);
    }

    // 3. Billing deduction
    const billingResult = await billing.deductCredit(
      keyRecord.developerId,
      CREDIT_COST_PER_CALL,
    );
    if (!billingResult.success) {
      const error = new PaymentRequiredError('Payment Required: insufficient balance');
      return next(error);
    }

    // 4. Proxy to upstream
    let upstreamStatus = 502;
    let upstreamBody: string = '{"error":"Bad Gateway"}';
    const timer = startUpstreamTimer(req.params.apiId, req.method);

    try {
      const upstreamRes = await fetch(`${upstreamUrl}${req.path}`, {
        method: req.method,
        headers: { 'Content-Type': 'application/json' },
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body),
      });

      upstreamStatus = upstreamRes.status;
      upstreamBody = await upstreamRes.text();
      timer.stop(upstreamStatus, 'success');
    } catch {
      upstreamStatus = 502;
      upstreamBody = JSON.stringify({ error: 'Bad Gateway: upstream unreachable' });
      timer.stop(upstreamStatus, 'error');
    }

    // 5. Record usage event
    usageStore.record({
      id: randomUUID(),
      requestId: randomUUID(), // legacy gateway doesn't carry request ID
      apiKey: apiKeyHeader,
      apiKeyId: keyRecord.key,
      apiId: keyRecord.apiId,
      endpointId: 'legacy',
      userId: keyRecord.developerId,
      amountUsdc: CREDIT_COST_PER_CALL,
      statusCode: upstreamStatus,
      timestamp: new Date().toISOString(),
    });

    // 6. Return upstream response
    res.status(upstreamStatus);
    try {
      res.json(JSON.parse(upstreamBody));
    } catch {
      res.send(upstreamBody);
    }
  });

  return router;
}
