import { describe, it, expect } from 'vitest';
import { toolOutputSchema, TOOL_RESULT_OUTPUT_SHAPE } from '../../src/helpers/output-schema.js';

describe('toolOutputSchema', () => {
  it('always returns the envelope schema (the compact profile drops it in the tool gate)', () => {
    expect(toolOutputSchema()).toBe(TOOL_RESULT_OUTPUT_SHAPE);
  });
});
