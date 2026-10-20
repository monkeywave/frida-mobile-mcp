import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';

export function createStdioTransport(): StdioServerTransport {
  return new StdioServerTransport();
}
