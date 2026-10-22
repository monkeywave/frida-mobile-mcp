/**
 * `search_recipes`: purpose-indexed lookup over the classic-JS recipe library
 * (src/recipes/). Returns ranked recipes with their source so the AI can read, adapt and
 * run one via execute_script. No device is touched.
 */
import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { listRecipes, searchRecipes } from '../recipes/registry.js';

export function registerRecipesTool(server: McpServer): void {
  server.registerTool(
    'search_recipes',
    {
      title: 'Search Recipe Library',
      description:
        'Search the purpose-indexed library of ready-to-run classic-JS Frida recipes (custom Java crypto-key capture, standard javax.crypto key/IV, native export hook, JNI RegisterNatives discovery, custom-classloader enumeration, intent/deeplink trace, WebView bridge, iOS Keychain). Returns ranked recipes with their classic-JS source and usage notes; adapt the source and run it with execute_script. An empty query lists the whole library.',
      inputSchema: z.object({
        query: z.string().optional().default('').describe('Free-text query over recipe name/title/tags/purpose (e.g. "rc4 key", "jni", "keychain"). Empty lists all recipes.'),
        platform: z.enum(['android', 'ios']).optional().describe('Restrict to recipes that do something on this platform.'),
        include_source: z.boolean().optional().default(true).describe('Include the full classic-JS source of each match (default true). Set false for a lighter catalog listing.'),
        limit: z.number().int().positive().optional().default(10).describe('Max recipes to return (default 10).'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ query, platform, include_source, limit, response_format }) => {
      try {
        let matches = searchRecipes(query ?? '');
        if (platform) matches = matches.filter((r) => r.platforms.includes(platform));
        const limited = matches.slice(0, limit ?? 10);
        const recipes = limited.map((r) => ({
          name: r.name,
          title: r.title,
          purpose: r.purpose,
          platforms: r.platforms,
          tags: r.tags,
          options: r.options,
          usage: r.usage,
          ...(include_source !== false ? { source: r.source } : {}),
        }));

        return formatToolResponse(
          buildResult(
            {
              query: query ?? '',
              total: listRecipes().length,
              matched: matches.length,
              returned: recipes.length,
              recipes,
            },
            [
              { tool: 'execute_script', reason: 'Adapt a recipe source and run it (requires allowCustomScripts)' },
              { tool: 'describe_class', reason: 'Confirm a class/overload before adapting a Java recipe' },
              { tool: 'save_script', reason: 'Save an adapted recipe for reuse' },
            ],
            {
              limitations:
                recipes.length === 0
                  ? ['No recipe matched the query. Call search_recipes with an empty query to see the whole library.']
                  : [],
            }
          ),
          response_format
        );
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}
