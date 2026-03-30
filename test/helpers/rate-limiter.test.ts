import { describe, it, expect, beforeEach } from 'vitest';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';

describe('RateLimiter', () => {
  beforeEach(() => {
    rateLimiter.reset();
  });

  it('allows calls within limit', () => {
    for (let i = 0; i < 5; i++) {
      expect(() => rateLimiter.check('test', 10)).not.toThrow();
      rateLimiter.record('test');
    }
  });

  it('throws RateLimitError when limit exceeded', () => {
    for (let i = 0; i < 10; i++) {
      rateLimiter.check('test', 10);
      rateLimiter.record('test');
    }
    expect(() => rateLimiter.check('test', 10)).toThrow('Rate limit exceeded');
  });

  it('tracks categories independently', () => {
    for (let i = 0; i < 5; i++) {
      rateLimiter.record('cat_a');
    }
    expect(() => rateLimiter.check('cat_b', 5)).not.toThrow();
  });

  it('allows unlimited when limit is 0', () => {
    for (let i = 0; i < 100; i++) {
      rateLimiter.record('test');
    }
    expect(() => rateLimiter.check('test', 0)).not.toThrow();
  });

  it('resets all state', () => {
    for (let i = 0; i < 10; i++) {
      rateLimiter.record('test');
    }
    rateLimiter.reset();
    expect(() => rateLimiter.check('test', 10)).not.toThrow();
  });
});
