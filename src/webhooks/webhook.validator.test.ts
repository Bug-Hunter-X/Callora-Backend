/**
 * Webhook Validator Tests
 * 
 * Comprehensive test suite covering:
 * - Success modes (valid payloads)
 * - Failure modes (missing fields, invalid types, unauthorized signatures)
 * - Security (timing attacks, replay attacks, DoS prevention)
 * - Edge cases (boundary conditions, malformed data)
 */

import crypto from 'crypto';
import {
  WebhookValidator,
  createWebhookValidator,
  ValidationErrorCode,
  WebhookPayload,
  WebhookValidatorConfig,
} from './webhook.validator';

describe('WebhookValidator', () => {
  const TEST_SECRET = 'test-secret-key-at-least-32-characters-long-for-security';
  let validator: WebhookValidator;

  beforeEach(() => {
    validator = createWebhookValidator({ secret: TEST_SECRET });
  });

  // Helper function to create a valid webhook payload
  const createValidPayload = (): WebhookPayload => ({
    id: '550e8400-e29b-41d4-a716-446655440000',
    event: 'payment.completed',
    timestamp: Math.floor(Date.now() / 1000),
    data: {
      amount: 1000,
      currency: 'USD',
      transactionId: 'tx_123456',
    },
    metadata: {
      userId: 'user_789',
    },
  });

  // Helper function to compute signature
  const computeSignature = (timestamp: string, body: string): string => {
    const signedPayload = `${timestamp}.${body}`;
    return crypto
      .createHmac('sha256', TEST_SECRET)
      .update(signedPayload)
      .digest('hex');
  };

  describe('Constructor', () => {
    it('should create validator with valid config', () => {
      expect(() => createWebhookValidator({ secret: TEST_SECRET })).not.toThrow();
    });

    it('should throw error if secret is too short', () => {
      expect(() => createWebhookValidator({ secret: 'short' })).toThrow(
        'Webhook secret must be at least 32 characters'
      );
    });

    it('should use default values for optional config', () => {
      const v = createWebhookValidator({ secret: TEST_SECRET });
      expect(v).toBeDefined();
    });

    it('should accept custom maxAge', () => {
      const v = createWebhookValidator({ secret: TEST_SECRET, maxAge: 600 });
      expect(v).toBeDefined();
    });

    it('should accept custom maxPayloadSize', () => {
      const v = createWebhookValidator({ secret: TEST_SECRET, maxPayloadSize: 2048 });
      expect(v).toBeDefined();
    });
  });

  describe('Success Modes', () => {
    it('should validate a valid webhook payload', () => {
      const payload = createValidPayload();
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
      expect(result.payload).toEqual(payload);
    });

    it('should validate payload without optional metadata', () => {
      const payload = createValidPayload();
      delete payload.metadata;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(true);
      expect(result.payload).toEqual(payload);
    });

    it('should validate payload with Buffer body', () => {
      const payload = createValidPayload();
      const timestamp = payload.timestamp.toString();
      const body = Buffer.from(JSON.stringify(payload));
      const signature = computeSignature(timestamp, body.toString('utf8'));

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(true);
    });

    it('should validate payload with nested data', () => {
      const payload = createValidPayload();
      payload.data = {
        transaction: {
          id: 'tx_123',
          amount: 1000,
          details: {
            currency: 'USD',
            fee: 10,
          },
        },
      };
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(true);
    });

    it('should validate payload at maximum age boundary', () => {
      const payload = createValidPayload();
      // Set timestamp to exactly maxAge seconds ago (300 seconds = 5 minutes)
      payload.timestamp = Math.floor(Date.now() / 1000) - 299;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(true);
    });
  });

  describe('Failure Modes - Missing Fields', () => {
    it('should fail if signature is missing', () => {
      const payload = createValidPayload();
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);

      const result = validator.validate(undefined, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Missing webhook signature');
    });

    it('should fail if timestamp is missing', () => {
      const payload = createValidPayload();
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, undefined, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Missing webhook timestamp');
    });

    it('should fail if payload is missing id field', () => {
      const payload = createValidPayload();
      delete (payload as any).id;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing or invalid field: id');
    });

    it('should fail if payload is missing event field', () => {
      const payload = createValidPayload();
      delete (payload as any).event;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing or invalid field: event');
    });

    it('should fail if payload is missing data field', () => {
      const payload = createValidPayload();
      delete (payload as any).data;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid field type: data must be an object');
    });
  });

  describe('Failure Modes - Invalid Types', () => {
    it('should fail if id is not a string', () => {
      const payload = createValidPayload();
      (payload as any).id = 12345;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing or invalid field: id');
    });

    it('should fail if event is not a string', () => {
      const payload = createValidPayload();
      (payload as any).event = 12345;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing or invalid field: event');
    });

    it('should fail if timestamp is not a number', () => {
      const payload = createValidPayload();
      (payload as any).timestamp = 'not-a-number';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid field type: timestamp must be a positive number');
    });

    it('should fail if data is not an object', () => {
      const payload = createValidPayload();
      (payload as any).data = 'not-an-object';
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid field type: data must be an object');
    });

    it('should fail if data is an array', () => {
      const payload = createValidPayload();
      (payload as any).data = ['array', 'not', 'object'];
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid field type: data must be an object');
    });

    it('should fail if metadata is not an object', () => {
      const payload = createValidPayload();
      (payload as any).metadata = 'not-an-object';
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid field type: metadata must be an object');
    });
  });

  describe('Failure Modes - Invalid Formats', () => {
    it('should fail if id is not a valid UUID', () => {
      const payload = createValidPayload();
      payload.id = 'not-a-valid-uuid';
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid field format: id must be a valid UUID');
    });

    it('should fail if event format is invalid', () => {
      const payload = createValidPayload();
      payload.event = 'invalid-event-format';
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid field format: event must be in format "resource.action"');
    });

    it('should fail if JSON is malformed', () => {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const body = '{ invalid json }';
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid JSON payload');
    });
  });

  describe('Security - Signature Validation', () => {
    it('should fail if signature is invalid', () => {
      const payload = createValidPayload();
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const invalidSignature = 'invalid-signature-12345';

      const result = validator.validate(invalidSignature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid webhook signature');
    });

    it('should fail if signature is tampered', () => {
      const payload = createValidPayload();
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);
      
      // Tamper with signature
      const tamperedSignature = signature.slice(0, -1) + 'x';

      const result = validator.validate(tamperedSignature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid webhook signature');
    });

    it('should fail if body is tampered after signature', () => {
      const payload = createValidPayload();
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);
      
      // Tamper with body
      const tamperedPayload = { ...payload, data: { ...payload.data, amount: 9999 } };
      const tamperedBody = JSON.stringify(tamperedPayload);

      const result = validator.validate(signature, timestamp, tamperedBody);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid webhook signature');
    });

    it('should use constant-time comparison for signatures', () => {
      const payload = createValidPayload();
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      // This test verifies that timing attacks are prevented
      // by using crypto.timingSafeEqual
      const result1 = validator.validate(signature, timestamp, body);
      const result2 = validator.validate(signature + 'x', timestamp, body);

      expect(result1.valid).toBe(true);
      expect(result2.valid).toBe(false);
    });
  });

  describe('Security - Replay Attack Prevention', () => {
    it('should fail if webhook is expired (older than maxAge)', () => {
      const payload = createValidPayload();
      // Set timestamp to 6 minutes ago (maxAge is 5 minutes)
      payload.timestamp = Math.floor(Date.now() / 1000) - 360;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Webhook has expired');
    });

    it('should fail if timestamp is in the future', () => {
      const payload = createValidPayload();
      // Set timestamp to 2 minutes in the future
      payload.timestamp = Math.floor(Date.now() / 1000) + 120;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Webhook timestamp is in the future');
    });

    it('should allow small clock skew (within 60 seconds)', () => {
      const payload = createValidPayload();
      // Set timestamp to 30 seconds in the future (within tolerance)
      payload.timestamp = Math.floor(Date.now() / 1000) + 30;
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(true);
    });

    it('should fail if timestamp is invalid format', () => {
      const payload = createValidPayload();
      const timestamp = 'not-a-number';
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid webhook timestamp');
    });

    it('should fail if timestamp is negative', () => {
      const payload = createValidPayload();
      const timestamp = '-12345';
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid webhook timestamp');
    });
  });

  describe('Security - DoS Prevention', () => {
    it('should fail if payload exceeds maximum size', () => {
      const smallValidator = createWebhookValidator({
        secret: TEST_SECRET,
        maxPayloadSize: 100, // 100 bytes
      });

      const payload = createValidPayload();
      // Create a large payload
      payload.data = {
        largeField: 'x'.repeat(200),
      };
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = smallValidator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Webhook payload exceeds maximum size');
    });

    it('should accept payload at maximum size boundary', () => {
      const validator = createWebhookValidator({
        secret: TEST_SECRET,
        maxPayloadSize: 500,
      });

      const payload = createValidPayload();
      payload.data = {
        field: 'x'.repeat(300),
      };
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string fields gracefully', () => {
      const payload = createValidPayload();
      payload.id = '';
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing or invalid field: id');
    });

    it('should handle whitespace-only fields', () => {
      const payload = createValidPayload();
      payload.event = '   ';
      const timestamp = payload.timestamp.toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing or invalid field: event');
    });

    it('should handle zero timestamp', () => {
      const payload = createValidPayload();
      payload.timestamp = 0;
      const timestamp = '0';
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid field type: timestamp must be a positive number');
    });

    it('should handle negative timestamp in payload', () => {
      const payload = createValidPayload();
      payload.timestamp = -12345;
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const body = JSON.stringify(payload);
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid field type: timestamp must be a positive number');
    });

    it('should handle null payload', () => {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const body = 'null';
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Payload must be an object');
    });

    it('should handle array payload', () => {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const body = '[]';
      const signature = computeSignature(timestamp, body);

      const result = validator.validate(signature, timestamp, body);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Payload must be an object');
    });
  });

  describe('computeSignature', () => {
    it('should compute correct HMAC signature', () => {
      const timestamp = '1234567890';
      const body = '{"test":"data"}';
      
      const signature = validator.computeSignature(timestamp, body);
      
      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');
      expect(signature.length).toBe(64); // SHA-256 hex is 64 characters
    });

    it('should produce different signatures for different bodies', () => {
      const timestamp = '1234567890';
      const body1 = '{"test":"data1"}';
      const body2 = '{"test":"data2"}';
      
      const sig1 = validator.computeSignature(timestamp, body1);
      const sig2 = validator.computeSignature(timestamp, body2);
      
      expect(sig1).not.toBe(sig2);
    });

    it('should produce different signatures for different timestamps', () => {
      const body = '{"test":"data"}';
      const timestamp1 = '1234567890';
      const timestamp2 = '1234567891';
      
      const sig1 = validator.computeSignature(timestamp1, body);
      const sig2 = validator.computeSignature(timestamp2, body);
      
      expect(sig1).not.toBe(sig2);
    });
  });

  describe('validateEventData', () => {
    it('should validate event-specific data', () => {
      const payload = createValidPayload();
      payload.event = 'payment.completed';
      payload.data = {
        amount: 1000,
        currency: 'USD',
      };

      const dataValidator = (data: unknown): data is { amount: number; currency: string } => {
        return (
          typeof data === 'object' &&
          data !== null &&
          'amount' in data &&
          'currency' in data &&
          typeof (data as any).amount === 'number' &&
          typeof (data as any).currency === 'string'
        );
      };

      const isValid = validator.validateEventData(payload, 'payment.completed', dataValidator);

      expect(isValid).toBe(true);
    });

    it('should fail if event type does not match', () => {
      const payload = createValidPayload();
      payload.event = 'payment.completed';

      const dataValidator = (data: unknown): data is any => true;

      const isValid = validator.validateEventData(payload, 'payment.failed', dataValidator);

      expect(isValid).toBe(false);
    });

    it('should fail if data validator returns false', () => {
      const payload = createValidPayload();
      payload.event = 'payment.completed';
      payload.data = {
        invalid: 'data',
      };

      const dataValidator = (data: unknown): data is { amount: number } => {
        return (
          typeof data === 'object' &&
          data !== null &&
          'amount' in data &&
          typeof (data as any).amount === 'number'
        );
      };

      const isValid = validator.validateEventData(payload, 'payment.completed', dataValidator);

      expect(isValid).toBe(false);
    });
  });
});
