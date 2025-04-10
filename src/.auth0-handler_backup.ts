/**
 * Auth0 OAuth 2.0 Handler with Session Duration Control
 *
 * This module implements a secure OAuth 2.0 flow for Auth0 authentication with
 * strict session management and duration control.
 *
 * Key Features:
 * - Complete OAuth 2.0 authorization code flow implementation
 * - Strict 2-hour session management
 * - PKCE support for enhanced security
 * - Comprehensive error handling
 * - Detailed logging for debugging and monitoring
 *
 * Flow Overview:
 * 1. User initiates authentication
 * 2. Redirect to Auth0 authorization endpoint
 * 3. Handle callback with authorization code
 * 4. Exchange code for tokens
 * 5. Fetch user information
 * 6. Manage session duration
 * 7. Handle session expiration
 *
 * @module Auth0Handler
 * @see https://auth0.com/docs/api/authentication
 * @see https://auth0.com/docs/secure/tokens/refresh-tokens
 */

import type {
  AuthRequest,
  OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { Context, Hono } from 'hono';
import type { MiddlewareHandler } from 'hono';
import { layout, homeContent } from './utils';

interface ExtendedOAuthHelpers extends OAuthHelpers {
  getSession(request: Request): Promise<{
    props: Props;
    delete(): Promise<void>;
  } | null>;
  deleteSession(request: Request): Promise<void>;
  createSessionCookie(options: {
    maxAge: number;
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'Lax' | 'Strict' | 'None';
  }): Promise<string>;
}

interface HomeContent {
  sessionInfo?: {
    userEmail: string;
    userName: string | null;
    remainingMinutes: number;
  };
}

/**
 * Environment variables required for Auth0 OAuth configuration
 * These should be set in your Cloudflare Workers environment
 *
 * @interface Env
 * @see https://auth0.com/docs/get-started/applications/application-settings
 */
interface Env {
  /** Auth0 domain (tenant-specific) */
  AUTH0_DOMAIN: string;
  /** Auth0 client ID from application settings */
  AUTH0_CLIENT_ID: string;
  /** Auth0 client secret from application settings */
  AUTH0_CLIENT_SECRET: string;
}

/**
 * Valid HTTP status codes for content responses
 * Used to ensure consistent error handling across the application
 *
 * @type ContentfulStatusCode
 */
type ContentfulStatusCode =
  | 200 // OK
  | 201 // Created
  | 400 // Bad Request
  | 401 // Unauthorized
  | 403 // Forbidden
  | 404 // Not Found
  | 500 // Internal Server Error
  | 502 // Bad Gateway
  | 503 // Service Unavailable
  | 504; // Gateway Timeout

/**
 * Session properties interface
 * Defines the structure of data stored in the OAuth session
 *
 * @interface Props
 * @extends StandardSessionProps
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
  /** Profile picture URL */
  picture?: string;
  /** Session start timestamp */
  sessionStartTime: number;
}

/**
 * Auth0 user information response structure
 * Matches the Auth0 /userinfo endpoint response
 *
 * @interface Auth0UserInfo
 * @see https://auth0.com/docs/api/authentication#user-profile
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
 * Base OAuth error class
 * Provides consistent error handling structure across the application
 *
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
 * Invalid state parameter error
 * Thrown when OAuth state validation fails
 *
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
 * Token exchange error
 * Thrown when code-to-token exchange fails
 *
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
 * User data fetch error
 * Thrown when unable to retrieve user information
 *
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
 * Session expiration error
 * Thrown when a session has exceeded its maximum duration
 *
 * @class SessionExpirationError
 * @extends OAuthError
 */
class SessionExpirationError extends OAuthError {
  constructor(message = 'Session has expired') {
    super(message, 401 as ContentfulStatusCode);
    this.name = 'SessionExpirationError';
  }
}

/**
 * Constants for session management
 * Defines key timing and configuration values
 */
const SESSION_CONFIG = {
  /** Maximum session duration in milliseconds (2 hours) */
  MAX_DURATION: 2 * 60 * 60 * 1000,
  /** Warning threshold before expiration (15 minutes) */
  WARNING_THRESHOLD: 15 * 60 * 1000,
} as const;

/**
 * Error handler middleware
 * Provides consistent error handling and logging across the application
 *
 * @param {unknown} err - The error to handle
 * @param {Context} c - Hono context
 * @returns {Promise<Response>} JSON response with error details
 */
const errorHandler = async (
  err: unknown,
  c: Context<{
    Bindings: Env & { OAUTH_PROVIDER: ExtendedOAuthHelpers };
    Variables: {
      sessionInfo: {
        userId: string;
        email: string;
        sessionStartTime: number;
        remainingTime: number;
      };
    };
  }>
) => {
  const error = err instanceof Error ? err : new Error(String(err));
  const timestamp = new Date().toISOString();

  // Structured error logging
  console.error(`[${timestamp}] Error:`, {
    name: error.name,
    message: error.message,
    stack: error.stack,
    url: c.req.url,
    method: c.req.method,
    headers: Object.fromEntries(c.req.raw.headers.entries()),
  });

  // Handle OAuth-specific errors
  if (error instanceof OAuthError) {
    return new Response(
      JSON.stringify({
        error: error.name,
        message: error.message,
        timestamp,
      }),
      {
        status: error.statusCode,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
        },
      }
    );
  }

  // Handle unexpected errors
  return new Response(
    JSON.stringify({
      error: 'InternalServerError',
      message: 'An unexpected error occurred',
      timestamp,
    }),
    {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    }
  );
};

/**
 * Session validation middleware
 * Checks session duration and handles expiration
 *
 * @param {Context} c - Hono context
 * @param {Function} next - Next middleware function
 * @returns {Promise<Response>} Response or continues to next middleware
 */
const validateSession: MiddlewareHandler = async (c, next) => {
  try {
    console.log('Validating session:', {
      path: c.req.path,
      method: c.req.method,
      cookies: c.req.raw.headers.get('cookie'),
      timestamp: new Date().toISOString(),
    });

    // Skip auth check for OPTIONS requests
    if (c.req.method === 'OPTIONS') {
      return next();
    }

    const session = await c.env.OAUTH_PROVIDER.getSession(c.req.raw);

    if (!session) {
      console.log('No session found, initiating auth flow');
      // For SSE requests, we want to redirect to auth
      if (c.req.path === '/sse') {
        const authUrl = new URL('/authorize', c.req.url);
        authUrl.searchParams.set('redirect_uri', c.req.url);
        return Response.redirect(authUrl.toString(), 302);
      }

      return new Response('Unauthorized - Session required', {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': 'http://localhost:6274',
          'Access-Control-Allow-Credentials': 'true',
        },
      });
    }
    return next();
  } catch (err: unknown) {
    console.error('Session validation error:', err);
    return new Response('Internal Server Error', { status: 500 });
  }
};

// Initialize Hono app with environment bindings
const auth0App = new Hono<{
  Bindings: Env & {
    OAUTH_PROVIDER: ExtendedOAuthHelpers;
  };
  Variables: {
    sessionInfo: {
      userId: string;
      email: string;
      sessionStartTime: number;
      remainingTime: number;
    };
  };
}>();

// Apply global error handler
auth0App.onError((err, c) => errorHandler(err, c));

/**
 * Security headers middleware
 * Adds security-related headers to all responses
 */
auth0App.use('*', async (c, next) => {
  await next();
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header(
    'Content-Security-Policy',
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; " +
      "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; " +
      "font-src 'self' data:;"
  );
});

/**
 * Homepage endpoint
 * Renders the application homepage with session status
 *
 * @route GET /
 */
auth0App.get('/', async (c) => {
  try {
    const content = await homeContent(c.req.raw);
    return c.html(layout(content, 'MCP Remote Auth Demo - Home'));
  } catch (err: unknown) {
    return errorHandler(err, c);
  }
});

// Define the Props interface for session properties
interface ExtendedOAuthHelpers extends OAuthHelpers {
  getSession(request: Request): Promise<{
    props: Props;
    delete(): Promise<void>;
  } | null>;
  deleteSession(request: Request): Promise<void>;
  createSessionCookie(options: {
    maxAge: number;
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'Lax' | 'Strict' | 'None';
  }): Promise<string>;
  // Add this line
  handleRequest(request: Request): Promise<Response>;
}

// Create a subrouter for the /sse endpoint
const sseRouter = new Hono<{
  Bindings: Env & { OAUTH_PROVIDER: ExtendedOAuthHelpers };
  Variables: {
    sessionInfo: {
      userId: string;
      email: string;
      sessionStartTime: number;
      remainingTime: number;
    };
  };
}>();

// Add the routes to the subrouter
sseRouter
  .use(validateSession)
  .get('/', async (c) => {
    try {
      console.log('SSE connection attempt:', {
        url: c.req.url,
        method: c.req.method,
        headers: Object.fromEntries(c.req.raw.headers.entries()),
        cookies: c.req.raw.headers.get('cookie'),
        timestamp: new Date().toISOString(),
      });

      const session = await c.env.OAUTH_PROVIDER.getSession(c.req.raw);

      if (!session) {
        console.log('No valid session found, redirecting to auth');
        // For SSE requests, we want to redirect to auth
        const authUrl = new URL('/authorize', c.req.url);
        authUrl.searchParams.set('redirect_uri', c.req.url);

        return Response.redirect(authUrl.toString(), 302);
      }

      console.log('Valid session found:', {
        userId: session.props.id,
        email: session.props.email,
        timestamp: new Date().toISOString(),
      });

      // If we have a valid session, proceed with SSE connection
      return c.env.OAUTH_PROVIDER.handleRequest(c.req.raw);
    } catch (err: unknown) {
      console.error('SSE connection error:', {
        error: err instanceof Error ? err.message : String(err),
        stack: err instanceof Error ? err.stack : undefined,
        timestamp: new Date().toISOString(),
      });
      return errorHandler(err, c);
    }
  })
  .options('/', async (c) => {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:6274',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400',
      },
    });
  });

/**
 * SSE endpoint
 * Handles the Server-Sent Events (SSE) connection
 * This endpoint is used to establish a connection for real-time updates
 * and is protected by session validation middleware.
 *
 * @route GET /sse
 */
auth0App.route('/sse', sseRouter);

/**
 * Authorization endpoint
 * Initiates the OAuth flow by redirecting to Auth0's authorization page
 *
 * @route GET /authorize
 * @see https://auth0.com/docs/api/authentication#authorize-application
 */
auth0App.get('/authorize', async (c) => {
  try {
    console.log('Starting Auth0 authorization process...');
    const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);

    console.log('OAuth request info:', {
      clientId: oauthReqInfo.clientId ? 'present' : 'missing',
      scope: oauthReqInfo.scope,
      timestamp: new Date().toISOString(),
    });

    // Validate client ID
    if (!oauthReqInfo.clientId) {
      throw new OAuthError('Missing client ID', 400 as ContentfulStatusCode);
    }

    // Validate required environment variables
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

    // Generate and store PKCE challenge
    const codeVerifier = crypto.randomUUID();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Store PKCE verifier in state
    const enhancedState = {
      ...oauthReqInfo,
      codeVerifier,
      timestamp: Date.now(),
    };

    const redirectUri = new URL('/callback', c.req.url).href;
    console.log('Generated redirect URI:', redirectUri);

    // Construct Auth0 authorization URL with PKCE
    const authorizeUrl = new URL(`https://${c.env.AUTH0_DOMAIN}/authorize`);
    authorizeUrl.searchParams.append('response_type', 'code');
    authorizeUrl.searchParams.append('client_id', c.env.AUTH0_CLIENT_ID);
    authorizeUrl.searchParams.append('redirect_uri', redirectUri);
    authorizeUrl.searchParams.append(
      'scope',
      'openid profile email offline_access'
    );
    authorizeUrl.searchParams.append('code_challenge', codeChallenge);
    authorizeUrl.searchParams.append('code_challenge_method', 'S256');
    authorizeUrl.searchParams.append(
      'state',
      btoa(JSON.stringify(enhancedState))
    );

    console.log(
      'Authorization URL generated (partial):',
      authorizeUrl.origin + authorizeUrl.pathname
    );

    return Response.redirect(authorizeUrl.toString(), 302);
  } catch (err: unknown) {
    return errorHandler(err, c);
  }
});

/**
 * Generates a PKCE code challenge from a code verifier
 * @param {string} verifier - The code verifier
 * @returns {Promise<string>} The code challenge
 */
async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Callback endpoint
 * Handles the OAuth callback, exchanges code for tokens, and completes authorization
 *
 * @route GET /callback
 * @see https://auth0.com/docs/api/authentication#get-token
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
      timestamp: new Date().toISOString(),
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
    let oauthReqInfo: AuthRequest & { codeVerifier: string; timestamp: number };
    try {
      oauthReqInfo = JSON.parse(atob(state));
      console.log('Successfully parsed state parameter');

      // Validate state timestamp
      const stateAge = Date.now() - oauthReqInfo.timestamp;
      if (stateAge > 300000) {
        // 5 minutes
        throw new InvalidStateError('State parameter has expired');
      }
    } catch (parseError) {
      console.error('State parameter parse error:', parseError);
      throw new InvalidStateError('Failed to decode state parameter');
    }

    if (!oauthReqInfo.clientId || !oauthReqInfo.codeVerifier) {
      console.error('Missing required state parameters');
      throw new InvalidStateError();
    }

    const redirectUri = new URL('/callback', c.req.url).href;
    console.log('Token exchange redirect URI:', redirectUri);

    // Exchange authorization code for access token with PKCE
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
          code_verifier: oauthReqInfo.codeVerifier,
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

    const tokenData = (await tokenResponse.json()) as { access_token: string };
    console.log('Successfully obtained access token');

    // Fetch user information with the new access token
    console.log('Fetching user information...');
    const userResponse = await fetch(`https://${c.env.AUTH0_DOMAIN}/userinfo`, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: 'application/json',
      },
    });

    if (!userResponse.ok) {
      console.error('User info request failed:', {
        status: userResponse.status,
        statusText: userResponse.statusText,
        timestamp: new Date().toISOString(),
      });
      throw new UserDataError(
        `API returned ${userResponse.status}: ${userResponse.statusText}`
      );
    }

    const userData = (await userResponse.json()) as Auth0UserInfo;
    console.log('Received user data:', {
      sub: userData.sub ? 'present' : 'missing',
      email: userData.email ? 'present' : 'missing',
      name: userData.name ? 'present' : 'missing',
      timestamp: new Date().toISOString(),
    });

    // Validate required user information
    if (!userData.sub || !userData.email) {
      throw new UserDataError('Missing required user information');
    }

    // Complete the authorization process with session management
    console.log('Completing authorization...');
    try {
      const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
        request: oauthReqInfo,
        userId: userData.sub,
        metadata: {
          label: userData.name,
          email: userData.email,
          locale: userData.locale,
        },
        scope: oauthReqInfo.scope,
        props: {
          id: userData.sub,
          name: userData.name || null,
          email: userData.email,
          picture: userData.picture || '',
          accessToken: tokenData.access_token,
          sessionStartTime: Date.now(), // Initialize session timestamp
        } as Props,
      });

      // Set secure session cookie
      const sessionCookie = await c.env.OAUTH_PROVIDER.createSessionCookie({
        maxAge: SESSION_CONFIG.MAX_DURATION / 1000, // Convert to seconds
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      });

      console.log('Authorization completed successfully');

      // Return response with session cookie
      return new Response(null, {
        status: 302,
        headers: {
          Location: redirectTo,
          'Set-Cookie': sessionCookie,
          'Cache-Control': 'no-store, no-cache, must-revalidate',
        },
      });
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      console.error('Failed to complete authorization:', {
        error: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString(),
      });
      throw new OAuthError(
        `Failed to complete authorization: ${error.message}`,
        500 as ContentfulStatusCode
      );
    }
  } catch (err: unknown) {
    return errorHandler(err, c);
  }
});

/**
 * Logout endpoint
 * Handles user logout and session cleanup
 *
 * @route POST /logout
 * @see https://auth0.com/docs/api/authentication#logout
 */
auth0App.post('/logout', async (c) => {
  try {
    const session = await c.env.OAUTH_PROVIDER.getSession(c.req.raw);

    if (session) {
      // Clear local session
      await c.env.OAUTH_PROVIDER.deleteSession(c.req.raw);

      // Construct Auth0 logout URL
      const logoutUrl = new URL(`https://${c.env.AUTH0_DOMAIN}/v2/logout`);
      logoutUrl.searchParams.append('client_id', c.env.AUTH0_CLIENT_ID);
      logoutUrl.searchParams.append('returnTo', new URL('/', c.req.url).href);

      return Response.redirect(logoutUrl.toString(), 302);
    }

    // If no session exists, redirect to home
    return Response.redirect('/', 302);
  } catch (err: unknown) {
    return errorHandler(err, c);
  }
});

/**
 * Session information endpoint
 * Returns current session status and remaining time
 *
 * @route GET /api/session
 * @protected
 */
auth0App.get('/api/session', validateSession, async (c) => {
  const sessionInfo = c.get('sessionInfo');

  return c.json({
    status: 'active',
    email: sessionInfo.email,
    remainingSeconds: Math.floor(sessionInfo.remainingTime / 1000),
    expiresAt: new Date(
      sessionInfo.sessionStartTime + SESSION_CONFIG.MAX_DURATION
    ).toISOString(),
  });
});

/**
 * Health check endpoint
 * Verifies the application's health status
 *
 * @route GET /health
 */
auth0App.get('/health', async (c) => {
  return c.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
});

// Export the configured application
export const Auth0Handler = auth0App;

/**
 * Type guard to verify Auth0UserInfo shape
 * @param {unknown} data - Data to verify
 * @returns {boolean} Whether the data matches Auth0UserInfo shape
 */
function isAuth0UserInfo(data: unknown): data is Auth0UserInfo {
  if (!data || typeof data !== 'object') return false;

  const user = data as Partial<Auth0UserInfo>;
  return (
    typeof user.sub === 'string' &&
    typeof user.email === 'string' &&
    (user.name === undefined || typeof user.name === 'string') &&
    (user.picture === undefined || typeof user.picture === 'string')
  );
}
