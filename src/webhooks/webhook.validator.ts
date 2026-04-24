/**
 * Webhook Validator
 * 
 * Provides secure validation for incoming webhook payloads with:
 * - HMAC signature verification (constant-time comparison)
 * - Timestamp validation (replay attack prevention)
 * - Payload size limits (DoS prevention)
 * - Schema validation (type safety)
 * - Defensive error handling (no information leakage)
 * 
 * @module webhooks/webhook.validator
 */

import crypto from 'crypto';

/**
 * Configuration for webhook validation
 */
export interface WebhookValidatorConfig {
  /** Secret key for HMAC signature verification */
  secret: string;
  /** Maximum age of webhook in seconds (default: 300 = 5 minutes) */
  maxAge?: number;
  /** Maximum payload size in bytes (default: 1MB) */
  maxPayloadSize?: number;
  /** Algorithm for HMAC (default: sha256) */
  algorithm?: string;
}

/**
 * Webhook payload structure
 */
export interface WebhookPayload {
  /** Unique identifier for the webhook event */
  id: string;
  /** Event type (e.g., 'payment.completed', 'transaction.confirmed') */
  event: string;
  /** Unix timestamp in seconds when the webhook was created */
  timestamp: number;
  /** Event-specific data */
  data: Record<string, unknown>;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Webhook validation result
 */
export interface ValidationResult {
  /** Whether the webhook is valid */
  valid: boolean;
  /** Error message if validation failed (safe for client response) */
  error?: string;
  /** Validated payload if successful */
  payload?: WebhookPayload;
}

/**
 * Webhook validation error codes
 */
export enum ValidationErrorCode {
  MISSING_SIGNATURE = 'MISSING_SIGNATURE',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  MISSING_TIMESTAMP = 'MISSING_TIMESTAMP',
  INVALID_TIMESTAMP = 'INVALID_TIMESTAMP',
  EXPIRED_WEBHOOK = 'EXPIRED_WEBHOOK',
  PAYLOAD_TOO_LARGE = 'PAYLOAD_TOO_LARGE',
  INVALID_PAYLOAD = 'INVALID_PAYLOAD',
  MISSING_REQUIRED_FIELD = 'MISSING_REQUIRED_FIELD',
  INVALID_FIELD_TYPE = 'INVALID_FIELD_TYPE',
}

/**
 * Custom error class for webhook validation failures
 */
export class WebhookValidationError extends Error {
  constructor(
    public code: ValidationErrorCode,
    message: string,
    public statusCode: number = 400
  ) {
    super(message);
    this.name = 'WebhookValidationError';
  }
}

/**
 * WebhookValidator class
 * 
 * Provides methods for secure webhook validation with defense against:
 * - Timing attacks (constant-time signature comparison)
 * - Replay attacks (timestamp validation)
 * - DoS attacks (payload size limits)
 * - Data tampering (HMAC signature verification)
 * - Malformed payloads (schema validation)
 */
export class WebhookValidator {
  private readonly secret: string;
  private readonly maxAge: number;
  private readonly maxPayloadSize: number;
  private readonly algorithm: string;

  constructor(config: WebhookValidatorConfig) {
    if (!config.secret || config.secret.length < 32) {
      throw new Error('Webhook secret must be at least 32 characters');
    }

    this.secret = config.secret;
    this.maxAge = config.maxAge ?? 300; // 5 minutes default
    this.maxPayloadSize = config.maxPayloadSize ?? 1024 * 1024; // 1MB default
    this.algorithm = config.algorithm ?? 'sha256';
  }

  /**
   * Validates a webhook request
   * 
   * @param signature - HMAC signature from request header
   * @param timestamp - Timestamp from request header (Unix seconds)
   * @param rawBody - Raw request body (string or Buffer)
   * @returns ValidationResult with validation status and payload
   */
  public validate(
    signature: string | undefined,
    timestamp: string | undefined,
    rawBody: string | Buffer
  ): ValidationResult {
    try {
      // Step 1: Validate signature presence
      if (!signature) {
        throw new WebhookValidationError(
          ValidationErrorCode.MISSING_SIGNATURE,
          'Missing webhook signature',
          401
        );
      }

      // Step 2: Validate timestamp presence
      if (!timestamp) {
        throw new WebhookValidationError(
          ValidationErrorCode.MISSING_TIMESTAMP,
          'Missing webhook timestamp',
          400
        );
      }

      // Step 3: Validate payload size (DoS prevention)
      const bodySize = Buffer.isBuffer(rawBody) ? rawBody.length : Buffer.byteLength(rawBody);
      if (bodySize > this.maxPayloadSize) {
        throw new WebhookValidationError(
          ValidationErrorCode.PAYLOAD_TOO_LARGE,
          'Webhook payload exceeds maximum size',
          413
        );
      }

      // Step 4: Parse and validate timestamp
      const timestampNum = parseInt(timestamp, 10);
      if (isNaN(timestampNum) || timestampNum <= 0) {
        throw new WebhookValidationError(
          ValidationErrorCode.INVALID_TIMESTAMP,
          'Invalid webhook timestamp',
          400
        );
      }

      // Step 5: Check timestamp age (replay attack prevention)
      const currentTime = Math.floor(Date.now() / 1000);
      const age = currentTime - timestampNum;
      
      if (age > this.maxAge) {
        throw new WebhookValidationError(
          ValidationErrorCode.EXPIRED_WEBHOOK,
          'Webhook has expired',
          400
        );
      }

      // Prevent future timestamps (clock skew tolerance: 60 seconds)
      if (age < -60) {
        throw new WebhookValidationError(
          ValidationErrorCode.INVALID_TIMESTAMP,
          'Webhook timestamp is in the future',
          400
        );
      }

      // Step 6: Verify HMAC signature (timing attack prevention)
      const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
      const expectedSignature = this.computeSignature(timestamp, bodyString);
      
      if (!this.secureCompare(signature, expectedSignature)) {
        throw new WebhookValidationError(
          ValidationErrorCode.INVALID_SIGNATURE,
          'Invalid webhook signature',
          401
        );
      }

      // Step 7: Parse and validate payload structure
      let payload: WebhookPayload;
      try {
        payload = JSON.parse(bodyString);
      } catch (error) {
        throw new WebhookValidationError(
          ValidationErrorCode.INVALID_PAYLOAD,
          'Invalid JSON payload',
          400
        );
      }

      // Step 8: Validate payload schema
      this.validatePayloadSchema(payload);

      return {
        valid: true,
        payload,
      };
    } catch (error) {
      if (error instanceof WebhookValidationError) {
        return {
          valid: false,
          error: error.message,
        };
      }

      // Don't leak internal errors to clients
      return {
        valid: false,
        error: 'Webhook validation failed',
      };
    }
  }

  /**
   * Computes HMAC signature for a webhook payload
   * 
   * @param timestamp - Unix timestamp in seconds
   * @param body - Raw request body
   * @returns HMAC signature as hex string
   */
  public computeSignature(timestamp: string, body: string): string {
    const signedPayload = `${timestamp}.${body}`;
    return crypto
      .createHmac(this.algorithm, this.secret)
      .update(signedPayload)
      .digest('hex');
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   * 
   * @param a - First string
   * @param b - Second string
   * @returns true if strings are equal
   */
  private secureCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    // Use crypto.timingSafeEqual for constant-time comparison
    const bufferA = Buffer.from(a, 'utf8');
    const bufferB = Buffer.from(b, 'utf8');

    try {
      return crypto.timingSafeEqual(bufferA, bufferB);
    } catch {
      return false;
    }
  }

  /**
   * Validates webhook payload schema
   * 
   * @param payload - Parsed webhook payload
   * @throws WebhookValidationError if schema validation fails
   */
  private validatePayloadSchema(payload: unknown): asserts payload is WebhookPayload {
    if (!payload || typeof payload !== 'object') {
      throw new WebhookValidationError(
        ValidationErrorCode.INVALID_PAYLOAD,
        'Payload must be an object',
        400
      );
    }

    const p = payload as Record<string, unknown>;

    // Validate required fields
    if (!p.id || typeof p.id !== 'string' || p.id.trim().length === 0) {
      throw new WebhookValidationError(
        ValidationErrorCode.MISSING_REQUIRED_FIELD,
        'Missing or invalid field: id',
        400
      );
    }

    if (!p.event || typeof p.event !== 'string' || p.event.trim().length === 0) {
      throw new WebhookValidationError(
        ValidationErrorCode.MISSING_REQUIRED_FIELD,
        'Missing or invalid field: event',
        400
      );
    }

    if (typeof p.timestamp !== 'number' || p.timestamp <= 0) {
      throw new WebhookValidationError(
        ValidationErrorCode.INVALID_FIELD_TYPE,
        'Invalid field type: timestamp must be a positive number',
        400
      );
    }

    if (!p.data || typeof p.data !== 'object' || Array.isArray(p.data)) {
      throw new WebhookValidationError(
        ValidationErrorCode.INVALID_FIELD_TYPE,
        'Invalid field type: data must be an object',
        400
      );
    }

    // Validate optional metadata field
    if (p.metadata !== undefined) {
      if (typeof p.metadata !== 'object' || Array.isArray(p.metadata)) {
        throw new WebhookValidationError(
          ValidationErrorCode.INVALID_FIELD_TYPE,
          'Invalid field type: metadata must be an object',
          400
        );
      }
    }

    // Validate id format (UUID v4 or similar)
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(p.id)) {
      throw new WebhookValidationError(
        ValidationErrorCode.INVALID_FIELD_TYPE,
        'Invalid field format: id must be a valid UUID',
        400
      );
    }

    // Validate event format (e.g., 'resource.action')
    const eventRegex = /^[a-z_]+\.[a-z_]+$/;
    if (!eventRegex.test(p.event)) {
      throw new WebhookValidationError(
        ValidationErrorCode.INVALID_FIELD_TYPE,
        'Invalid field format: event must be in format "resource.action"',
        400
      );
    }
  }

  /**
   * Validates a specific event type's data structure
   * 
   * @param payload - Validated webhook payload
   * @param eventType - Expected event type
   * @param dataValidator - Custom validation function for event data
   * @returns true if event data is valid
   */
  public validateEventData<T = Record<string, unknown>>(
    payload: WebhookPayload,
    eventType: string,
    dataValidator: (data: unknown) => data is T
  ): boolean {
    if (payload.event !== eventType) {
      return false;
    }

    return dataValidator(payload.data);
  }
}

/**
 * Creates a webhook validator instance with the provided configuration
 * 
 * @param config - Webhook validator configuration
 * @returns WebhookValidator instance
 */
export function createWebhookValidator(config: WebhookValidatorConfig): WebhookValidator {
  return new WebhookValidator(config);
}

/**
 * Express middleware for webhook validation
 * 
 * @param validator - WebhookValidator instance
 * @returns Express middleware function
 */
export function webhookValidationMiddleware(validator: WebhookValidator) {
  return (req: any, res: any, next: any) => {
    const signature = req.headers['x-webhook-signature'] as string | undefined;
    const timestamp = req.headers['x-webhook-timestamp'] as string | undefined;
    
    // Capture raw body for signature verification
    let rawBody = '';
    req.on('data', (chunk: Buffer) => {
      rawBody += chunk.toString('utf8');
    });

    req.on('end', () => {
      const result = validator.validate(signature, timestamp, rawBody);

      if (!result.valid) {
        return res.status(401).json({
          error: 'Webhook validation failed',
          message: result.error,
        });
      }

      // Attach validated payload to request
      req.webhookPayload = result.payload;
      next();
    });
  };
}
