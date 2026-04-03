import { z } from 'zod';

/** Maximum response size in characters to prevent overwhelming LLM context windows. */
export const CHARACTER_LIMIT = 25_000;


/**
 * Response format enum.
 * - toon (default): Token-Oriented Object Notation — ~40% fewer tokens than JSON with equal
 *   or better LLM comprehension. Always suggested as the preferred format.
 * - markdown: Human-readable fallback.
 * - json: Raw structured data, opt-in for programmatic use.
 */
export enum ResponseFormat {
  TOON = 'toon',
  MARKDOWN = 'markdown',
  JSON = 'json',
}

/** Reusable Zod schema fragment for the response_format parameter. */
export const responseFormatSchema = z.nativeEnum(ResponseFormat)
  .default(ResponseFormat.TOON)
  .describe('Output format: "toon" (default, ~40% fewer tokens — recommended), "markdown" for human-readable, "json" for raw structured data');
