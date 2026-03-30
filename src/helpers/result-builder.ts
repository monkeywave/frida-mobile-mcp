import type { ToolResult, SuggestedAction, SessionContext, ErrorResponse } from '../types.js';
import { getState } from '../state.js';
import { FridaMcpError } from './errors.js';

export function buildResult<T>(
  result: T,
  suggestedNext: SuggestedAction[] = []
): ToolResult<T> {
  const state = getState();
  return {
    result,
    session_context: state.getSessionContext(),
    suggested_next: suggestedNext,
  };
}

export function buildErrorResult(error: FridaMcpError): ErrorResponse {
  return error.toErrorResponse();
}

export function formatToolResponse(result: ToolResult | ErrorResponse): { content: Array<{ type: 'text'; text: string }>; isError?: boolean } {
  if ('error' in result) {
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      isError: true,
    };
  }
  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}
