/**
 * Auth0 OAuth 2.0 Handler
 */
import type {
  AuthRequest,
  OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import type { StatusCode } from 'hono/utils/http-status';
import { layout, homeContent } from './utils';

interface Env {
  AUTH0_DOMAIN: string;
  AUTH0_CLIENT_ID: string;
  AUTH0_CLIENT_SECRET: string;
}

interface Props {
  id: string;
  name: string | null;
  email: string;
  accessToken: string;
  picture?: string;
}

interface Auth0UserInfo {
  sub: string;
  name?: string;
  email: string;
  email_verified?: boolean;
  picture?: string;
  locale?: string;
}

// Custom error class for OAuth specific errors
class OAuthException extends HTTPException {
  constructor(status: StatusCode, message: string) {
    super(status as any, { message });
  }
}

// Initialize Hono app with environment bindings
const auth0App = new Hono<{
  Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers };
}>();

/**
 * Homepage endpoint
 */
auth0App.get('/', async (c) => {
  const content = await homeContent(c.req.raw);
  return c.html(layout(content, 'MCP Remote Auth Demo - Home'));
});

/**
 * Authorization endpoint
 */
auth0App.get('/authorize', async (c) => {
  console.log('Starting Auth0 authorization process...');
  const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);

  if (!oauthReqInfo.clientId) {
    throw new OAuthException(400, 'Missing client ID');
  }

  const { AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_DOMAIN } = c.env;
  if (!AUTH0_CLIENT_ID || !AUTH0_CLIENT_SECRET || !AUTH0_DOMAIN) {
    throw new OAuthException(500, 'OAuth configuration missing');
  }

  const redirectUri = 'https://remote-mcp.krishanka.workers.dev/callback';

  const authorizeUrl = new URL(`https://${AUTH0_DOMAIN}/authorize`);
  authorizeUrl.searchParams.append('response_type', 'code');
  authorizeUrl.searchParams.append('client_id', AUTH0_CLIENT_ID);
  authorizeUrl.searchParams.append('redirect_uri', redirectUri);
  authorizeUrl.searchParams.append('scope', 'openid profile email');
  authorizeUrl.searchParams.append('state', btoa(JSON.stringify(oauthReqInfo)));

  return Response.redirect(authorizeUrl.toString());
});

/**
 * Callback endpoint
 */
auth0App.get('/callback', async (c) => {
  console.log('Received callback request');
  const state = c.req.query('state');
  const code = c.req.query('code');
  const error = c.req.query('error');

  if (error) {
    throw new OAuthException(400, `Auth0 authorization error: ${error}`);
  }

  if (!state || !code) {
    throw new OAuthException(400, 'Missing required parameters');
  }

  // Validate and parse state parameter
  let oauthReqInfo: AuthRequest;
  try {
    oauthReqInfo = JSON.parse(atob(state)) as AuthRequest;
  } catch (parseError) {
    throw new OAuthException(400, 'Failed to decode state parameter');
  }

  if (!oauthReqInfo.clientId) {
    throw new OAuthException(400, 'Invalid state parameter');
  }

  const redirectUri = 'https://remote-mcp.krishanka.workers.dev/callback';

  // Exchange authorization code for access token
  const tokenResponse = await fetch(
    `https://${c.env.AUTH0_DOMAIN}/oauth/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: c.env.AUTH0_CLIENT_ID,
        client_secret: c.env.AUTH0_CLIENT_SECRET,
        code,
        redirect_uri: redirectUri,
      }),
    }
  );

  if (!tokenResponse.ok) {
    throw new OAuthException(401, 'Failed to exchange token');
  }

  const tokenData = await tokenResponse.json<{ access_token: string }>();

  // Fetch user information
  const userResponse = await fetch(`https://${c.env.AUTH0_DOMAIN}/userinfo`, {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });

  if (!userResponse.ok) {
    throw new OAuthException(
      500,
      `API returned ${userResponse.status}: ${userResponse.statusText}`
    );
  }

  const userData = await userResponse.json<Auth0UserInfo>();

  if (!userData.sub || !userData.email) {
    throw new OAuthException(500, 'Missing required user information');
  }

  // Complete the authorization process
  const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthReqInfo,
    userId: userData.sub,
    metadata: { label: userData.name },
    scope: oauthReqInfo.scope,
    props: {
      id: userData.sub,
      name: userData.name || null,
      email: userData.email,
      picture: userData.picture || '',
      accessToken: tokenData.access_token,
    } as Props,
  });

  return Response.redirect(redirectTo);
});

// Global error handler
auth0App.onError((err, c) => {
  console.error(`[${new Date().toISOString()}] Error:`, {
    name: err.name,
    message: err.message,
    stack: err instanceof Error ? err.stack : undefined,
    url: c.req.url,
  });

  if (err instanceof OAuthException) {
    return c.json(
      {
        error: err.name,
        message: err.message,
      },
      err.status
    );
  }

  // Handle unexpected errors
  return c.json(
    {
      error: 'InternalServerError',
      message: 'An unexpected error occurred',
    },
    500
  );
});

export const Auth0Handler = auth0App;
