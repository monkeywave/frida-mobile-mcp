// HTTP/SSE transport - Phase 6 implementation
// Will use StreamableHTTPServerTransport from @modelcontextprotocol/sdk
// and an Express server for SSE fallback.

export function createHttpTransport(_port: number): never {
  throw new Error(
    'HTTP transport is not yet implemented. Use --transport stdio for now.'
  );
}
