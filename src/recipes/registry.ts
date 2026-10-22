import type { Recipe } from './types.js';
import { customJavaCryptoRecipe, javaxCryptoRecipe } from './java-crypto-key.js';
import { nativeExportHookRecipe, registerNativesRecipe } from './native-hooks.js';
import { classloaderRecipe, intentTraceRecipe, webviewBridgeRecipe } from './android-misc.js';
import { keychainRecipe } from './ios-keychain.js';
import { androidKeystoreUsageRecipe } from './android-keystore-usage.js';
import { stringDecryptorHarnessRecipe } from './string-decryptor-harness.js';

/**
 * Purpose-indexed library of classic-JS recipe snippets (see src/recipes/types.ts). The
 * list is the single source of truth; resources and the search_recipes tool read it.
 */
const RECIPES: readonly Recipe[] = [
  customJavaCryptoRecipe,
  javaxCryptoRecipe,
  nativeExportHookRecipe,
  registerNativesRecipe,
  classloaderRecipe,
  intentTraceRecipe,
  webviewBridgeRecipe,
  keychainRecipe,
  androidKeystoreUsageRecipe,
  stringDecryptorHarnessRecipe,
];

export function listRecipes(): readonly Recipe[] {
  return RECIPES;
}

export function getRecipe(name: string): Recipe | undefined {
  return RECIPES.find((r) => r.name === name);
}

/**
 * Rank recipes against a free-text query over name/title/purpose/tags. Returns every recipe
 * with a non-zero score, best first; an empty query returns all recipes in registry order.
 */
export function searchRecipes(query: string): Recipe[] {
  const q = query.trim().toLowerCase();
  if (!q) return [...RECIPES];
  const terms = q.split(/\s+/);
  const scored = RECIPES.map((recipe) => {
    const haystacks = [
      { text: recipe.name.toLowerCase(), weight: 4 },
      { text: recipe.title.toLowerCase(), weight: 3 },
      { text: recipe.tags.join(' ').toLowerCase(), weight: 3 },
      { text: recipe.purpose.toLowerCase(), weight: 1 },
    ];
    let score = 0;
    for (const term of terms) {
      for (const { text, weight } of haystacks) {
        if (text.includes(term)) score += weight;
      }
    }
    return { recipe, score };
  });
  return scored
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((s) => s.recipe);
}
