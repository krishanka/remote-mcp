/**
 * Auth0 OAuth 2.0 Handler
 *
 * This module implements the OAuth 2.0 flow for Auth0 authentication.
 * It handles the authorization and callback endpoints required for the OAuth flow.
 *
 * The flow consists of:
 * 1. Redirecting users to Auth0's authorization page
 * 2. Handling the callback with authorization code
 * 3. Exchanging the code for access tokens
 * 4. Fetching user information
 * 5. Completing the authorization process
 *
 * @module Auth0Handler
 * @see https://auth0.com/docs/api/authentication
 */

import type {
  AuthRequest,
  OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { Hono } from 'hono';
import type { Context } from 'hono';

/**
 * Environment variables required for Auth0 OAuth configuration
 * @interface Env
 */
interface Env {
  /** Auth0 domain */
  AUTH0_DOMAIN: string;
  /** Auth0 client ID */
  AUTH0_CLIENT_ID: string;
  /** Auth0 client secret */
  AUTH0_CLIENT_SECRET: string;
}

type ContentfulStatusCode =
  | 200
  | 201
  | 400
  | 401
  | 403
  | 404
  | 500
  | 502
  | 503
  | 504;

/**
 * Base class for OAuth-related errors
 * @class OAuthError
 * @extends Error
 */
class OAuthError extends Error {
  constructor(message: string, public statusCode: ContentfulStatusCode) {
    super(message);
    this.name = 'OAuthError';
  }
}

/**
 * Error thrown when the state parameter is invalid or missing
 * @class InvalidStateError
 * @extends OAuthError
 */
class InvalidStateError extends OAuthError {
  constructor(message = 'Invalid state parameter') {
    super(message, 400 as ContentfulStatusCode);
    this.name = 'InvalidStateError';
  }
}

/**
 * Error thrown when token exchange fails
 * @class TokenExchangeError
 * @extends OAuthError
 */
class TokenExchangeError extends OAuthError {
  constructor(message = 'Failed to exchange token') {
    super(message, 401 as ContentfulStatusCode);
    this.name = 'TokenExchangeError';
  }
}

/**
 * Error thrown when user data fetch fails
 * @class UserDataError
 * @extends OAuthError
 */
class UserDataError extends OAuthError {
  constructor(message = 'Failed to fetch user data') {
    super(message, 500 as ContentfulStatusCode);
    this.name = 'UserDataError';
  }
}

/**
 * Properties stored in the OAuth session
 * @interface Props
 */
interface Props {
  /** Unique identifier for the user */
  id: string;
  /** User's display name */
  name: string | null;
  /** User's email address */
  email: string;
  /** OAuth access token */
  accessToken: string;
  /** Picture URL */
  picture?: string;
}

/**
 * Structure of Auth0's user info response
 * @interface Auth0UserInfo
 */
interface Auth0UserInfo {
  /** Auth0 user identifier */
  sub: string;
  /** User's full name */
  name?: string;
  /** User's email address */
  email: string;
  /** Email verification status */
  email_verified?: boolean;
  /** Profile picture URL */
  picture?: string;
  /** User locale */
  locale?: string;
}

/**
 * Error handler middleware
 * @param {unknown} err - The error to handle
 * @param {Context} c - Hono context
 * @returns {Promise<Response>} JSON response with error details
 */
const errorHandler = async (err: unknown, c: Context) => {
  const error = err instanceof Error ? err : new Error(String(err));

  console.error(`[${new Date().toISOString()}] Error:`, {
    name: error.name,
    message: error.message,
    stack: error.stack,
    url: c.req.url,
  });

  if (error instanceof OAuthError) {
    return new Response(
      JSON.stringify({
        error: error.name,
        message: error.message,
      }),
      {
        status: error.statusCode,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  return new Response(
    JSON.stringify({
      error: 'InternalServerError',
      message: 'An unexpected error occurred',
    }),
    {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    }
  );
};

// Initialize Hono app with environment bindings
const auth0App = new Hono<{
  Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers };
}>();

/**
 * Authorization endpoint
 * Initiates the OAuth flow by redirecting to Auth0's authorization page
 *
 * @route GET /authorize
 */
auth0App.get('/authorize', async (c) => {
  try {
    console.log('Starting Auth0 authorization process...');
    const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);

    console.log('OAuth request info:', {
      clientId: oauthReqInfo.clientId ? 'present' : 'missing',
      scope: oauthReqInfo.scope,
    });

    if (!oauthReqInfo.clientId) {
      throw new OAuthError('Missing client ID', 400 as ContentfulStatusCode);
    }

    if (
      !c.env.AUTH0_CLIENT_ID ||
      !c.env.AUTH0_CLIENT_SECRET ||
      !c.env.AUTH0_DOMAIN
    ) {
      console.error('Missing Auth0 configuration');
      throw new OAuthError(
        'OAuth configuration missing',
        500 as ContentfulStatusCode
      );
    }

    const redirectUri = new URL('/callback', c.req.url).href;
    console.log('Generated redirect URI:', redirectUri);

    const authorizeUrl = new URL(`https://${c.env.AUTH0_DOMAIN}/authorize`);
    authorizeUrl.searchParams.append('response_type', 'code');
    authorizeUrl.searchParams.append('client_id', c.env.AUTH0_CLIENT_ID);
    authorizeUrl.searchParams.append('redirect_uri', redirectUri);
    authorizeUrl.searchParams.append('scope', 'openid profile email');
    authorizeUrl.searchParams.append(
      'state',
      btoa(JSON.stringify(oauthReqInfo))
    );

    console.log(
      'Generated authorize URL (partial):',
      authorizeUrl.origin + authorizeUrl.pathname
    );
    return Response.redirect(authorizeUrl.toString());
  } catch (err: unknown) {
    return errorHandler(err, c);
  }
});

/**
 * Callback endpoint
 * Handles the OAuth callback, exchanges code for tokens, and completes authorization
 *
 * @route GET /callback
 */
auth0App.get('/callback', async (c) => {
  try {
    console.log('Received callback request');
    const state = c.req.query('state');
    const code = c.req.query('code');
    const error = c.req.query('error');

    console.log('Callback parameters:', {
      statePresent: !!state,
      codePresent: !!code,
      error: error || 'none',
    });

    if (error) {
      throw new OAuthError(
        `Auth0 authorization error: ${error}`,
        400 as ContentfulStatusCode
      );
    }

    if (!state || !code) {
      throw new OAuthError(
        'Missing required parameters',
        400 as ContentfulStatusCode
      );
    }

    // Validate and parse state parameter
    let oauthReqInfo: AuthRequest;
    try {
      oauthReqInfo = JSON.parse(atob(state)) as AuthRequest;
      console.log('Successfully parsed state parameter');
    } catch (parseError) {
      console.error('State parameter parse error:', parseError);
      throw new InvalidStateError('Failed to decode state parameter');
    }

    if (!oauthReqInfo.clientId) {
      console.error('Missing clientId in parsed state');
      throw new InvalidStateError();
    }

    const redirectUri = new URL('/callback', c.req.url).href;
    console.log('Token exchange redirect URI:', redirectUri);

    // Exchange authorization code for access token
    console.log('Attempting token exchange...');
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
      console.error('Token exchange failed:', {
        status: tokenResponse.status,
        statusText: tokenResponse.statusText,
      });
      throw new TokenExchangeError('Failed to exchange token');
    }

    const tokenData = await tokenResponse.json<{ access_token: string }>();
    console.log('Successfully obtained access token');

    // Fetch user information
    console.log('Fetching user information...');
    const userResponse = await fetch(`https://${c.env.AUTH0_DOMAIN}/userinfo`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    if (!userResponse.ok) {
      console.error('User info request failed:', {
        status: userResponse.status,
        statusText: userResponse.statusText,
      });
      throw new UserDataError(
        `API returned ${userResponse.status}: ${userResponse.statusText}`
      );
    }

    const userData = await userResponse.json<Auth0UserInfo>();
    console.log('Received user data:', {
      sub: userData.sub ? 'present' : 'missing',
      email: userData.email ? 'present' : 'missing',
      name: userData.name ? 'present' : 'missing',
    });

    if (!userData.sub || !userData.email) {
      throw new UserDataError('Missing required user information');
    }

    // Complete the authorization process
    console.log('Completing authorization...');
    try {
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

      console.log('Authorization completed successfully');
      return Response.redirect(redirectTo);
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      console.error('Failed to complete authorization:', error);
      throw new OAuthError(
        `Failed to complete authorization: ${error.message}`,
        500 as ContentfulStatusCode
      );
    }
  } catch (err: unknown) {
    return errorHandler(err, c);
  }
});

// Global error handler
auth0App.onError((err: unknown, c) => {
  return errorHandler(err, c);
});

export const Auth0Handler = auth0App;
