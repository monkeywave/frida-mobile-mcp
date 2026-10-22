/**
 * Recipe = a purpose-indexed, classic-JS Frida agent snippet meant to be read, adapted
 * and run (via execute_script) by an AI operator. Unlike a prebuilt ScriptTemplate, a
 * recipe is a *worked example*: the `source` is a constant classic-JavaScript string that
 * reads its parameters from `__FRIDA_MCP__.options` (never from spliced-in code) and runs
 * under the agent preamble (src/agent/preamble.ts), so it may use the preamble helpers
 * (findExport, hookNative, javaPerform, objcClassNames, reportSummary) and report results
 * with `send({ type, ... })`.
 *
 * Recipes are served read-only through the `frida://recipes` resources and searched with
 * the `search_recipes` tool; running one means pasting/adapting its `source` into
 * execute_script, so no per-recipe compile step exists (see HANDOFF §2).
 */
export type RecipePlatform = 'android' | 'ios';

export interface RecipeOption {
  /** Option key read from `__FRIDA_MCP__.options`. */
  name: string;
  description: string;
  /** Whether the recipe misbehaves / no-ops without it. */
  required: boolean;
  /** A concrete example value, shown in the recipe listing. */
  example: unknown;
}

export interface Recipe {
  /** Stable identifier used in `frida://recipes/{name}`. */
  name: string;
  /** Short human title. */
  title: string;
  /** One sentence: what analysis goal this recipe serves. */
  purpose: string;
  platforms: RecipePlatform[];
  /** Free-text keywords for `search_recipes`. */
  tags: string[];
  /** Options the `source` reads from `__FRIDA_MCP__.options`. */
  options: RecipeOption[];
  /** Classic-JS agent body (runs under the preamble; no imports, no TS). */
  source: string;
  /** How to run and adapt it, in prose. */
  usage: string;
}
