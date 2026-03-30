import { RateLimitError } from './errors.js';

class RateLimiter {
  private calls: Map<string, number[]> = new Map();

  check(category: string, limit: number): void {
    if (limit <= 0) return;
    const timestamps = this.calls.get(category);
    if (!timestamps || timestamps.length === 0) return;
    // Only prune if array could possibly exceed limit
    if (timestamps.length >= limit) {
      this.prune(category);
      const pruned = this.calls.get(category) || [];
      if (pruned.length >= limit) {
        throw new RateLimitError(category, limit);
      }
    }
  }

  record(category: string): void {
    if (!this.calls.has(category)) {
      this.calls.set(category, []);
    }
    this.calls.get(category)!.push(Date.now());
  }

  private prune(category: string): void {
    const timestamps = this.calls.get(category);
    if (!timestamps) return;
    const cutoff = Date.now() - 60_000; // 1 minute window
    const pruned = timestamps.filter((t) => t > cutoff);
    this.calls.set(category, pruned);
  }

  reset(): void {
    this.calls.clear();
  }
}

export const rateLimiter = new RateLimiter();
