import { McpAgent } from 'agents/mcp';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import OAuthProvider from '@cloudflare/workers-oauth-provider';
import { Auth0Handler } from './auth0-handler';

export class MyMCP extends McpAgent {
  server = new McpServer({
    name: 'remote-mcp',
    description:
      'My remote MCP server with OAuth, SSE running on Cloudflare exposing custom tools',
    version: '1.0.1',
  });

  async init() {
    this.server.tool(
      'add',
      'Add two numbers',
      { a: z.number(), b: z.number() },
      async ({ a, b }) => ({
        content: [{ type: 'text', text: String(a + b) }],
      })
    );
  }
}

// Export the OAuth handler as the default
export default new OAuthProvider({
  apiRoute: '/sse',
  // TODO: fix these types
  // @ts-ignore
  apiHandler: MyMCP.mount('/sse'),
  // @ts-ignore
  defaultHandler: Auth0Handler,
  authorizeEndpoint: '/authorize',
  tokenEndpoint: '/token',
  clientRegistrationEndpoint: '/register',
});
