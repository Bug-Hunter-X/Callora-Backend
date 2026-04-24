import express, { Request, Response, NextFunction } from 'express';
import { createWebhookValidator, WebhookPayload } from './webhooks/webhook.validator.js';

const app = express();
const PORT = process.env.PORT ?? 3000;

// Webhook secret from environment variable
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET ?? 'default-secret-key-at-least-32-characters-long-change-in-production';

// Create webhook validator instance
const webhookValidator = createWebhookValidator({
  secret: WEBHOOK_SECRET,
  maxAge: 300, // 5 minutes
  maxPayloadSize: 1024 * 1024, // 1MB
});

// Standard JSON middleware for non-webhook routes
app.use((req, res, next) => {
  if (req.path === '/api/webhooks') {
    // Skip JSON parsing for webhook route (we need raw body)
    next();
  } else {
    express.json()(req, res, next);
  }
});

// Health check endpoint
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'callora-backend' });
});

// APIs endpoint
app.get('/api/apis', (_req, res) => {
  res.json({ apis: [] });
});

// Usage endpoint
app.get('/api/usage', (_req, res) => {
  res.json({ calls: 0, period: 'current' });
});

// Webhook endpoint with validation
app.post('/api/webhooks', (req: Request, res: Response) => {
  const signature = req.headers['x-webhook-signature'] as string | undefined;
  const timestamp = req.headers['x-webhook-timestamp'] as string | undefined;

  // Collect raw body
  let rawBody = '';
  req.on('data', (chunk: Buffer) => {
    rawBody += chunk.toString('utf8');
  });

  req.on('end', () => {
    // Validate webhook
    const result = webhookValidator.validate(signature, timestamp, rawBody);

    if (!result.valid) {
      return res.status(401).json({
        success: false,
        error: 'Webhook validation failed',
        message: result.error,
      });
    }

    // Process validated webhook payload
    const payload = result.payload as WebhookPayload;

    // Log webhook event (in production, this would trigger business logic)
    console.log(`Received webhook: ${payload.event} (ID: ${payload.id})`);

    // Return success response
    res.status(200).json({
      success: true,
      message: 'Webhook received and validated',
      eventId: payload.id,
      eventType: payload.event,
    });
  });

  req.on('error', (error) => {
    console.error('Error reading webhook request:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  });
});

// Error handling middleware
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`Callora backend listening on http://localhost:${PORT}`);
    console.log(`Webhook endpoint: http://localhost:${PORT}/api/webhooks`);
  });
}

export default app;