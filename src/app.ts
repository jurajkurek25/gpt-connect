import { createHmac } from 'node:crypto';
import { hostHeaderValidation, requireBearerAuth } from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { buildOAuthProtectedResourceMetadata, createMcpHandler, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/server';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import type { Config } from './config.js';
import { MCP_SCOPE } from './config.js';
import type { Store } from './db.js';
import { GoogleCredentials } from './google/credentials.js';
import { type FetchFn, GoogleOAuthClient } from './google/oauth.js';
import { GoogleTasksClient } from './google/tasksClient.js';
import type { Logger } from './logger.js';
import { buildMcpServer } from './mcp/tools.js';
import { authorizationServerMetadata, createOAuthRouter, createTokenVerifier } from './oauth/server.js';
import { TasksService } from './tasks/service.js';

export interface AppDeps {
  config: Config;
  store: Store;
  logger: Logger;
  /** Injected for tests; production uses global fetch against fixed Google endpoints only. */
  fetchFn?: FetchFn;
  now?: () => number;
}

export interface AppBundle {
  app: Express;
  credentials: GoogleCredentials;
  service: TasksService;
}

export function createApp(deps: AppDeps): AppBundle {
  const { config, store, logger } = deps;
  const now = deps.now ?? Date.now;
  const fetchFn = deps.fetchFn ?? fetch;

  const googleOAuth = new GoogleOAuthClient(config, fetchFn, now);
  const credentials = new GoogleCredentials(store, googleOAuth, config.encryptionKey, logger, now);
  const api = new GoogleTasksClient(credentials, fetchFn);
  const hmacKey = createHmac('sha256', config.encryptionKey).update('delete-confirmation-key').digest();
  const service = new TasksService({ api, store, timezone: config.timezone, hmacKey, now });

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxyHops);

  // DNS rebinding protection: only the public hostname (plus localhost for container health checks).
  app.use(hostHeaderValidation([config.publicHost, 'localhost', '127.0.0.1']));

  const redirectOrigins = [...new Set(config.allowedRedirectUris.map((u) => new URL(u).origin))];
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'none'"],
          styleSrc: ["'unsafe-inline'"],
          formAction: ["'self'", 'https://accounts.google.com', ...redirectOrigins],
          frameAncestors: ["'none'"],
          baseUri: ["'none'"],
        },
      },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );

  // Access log without query strings (OAuth codes and state travel in query strings).
  app.use((req: Request, res: Response, next: NextFunction) => {
    const start = now();
    res.on('finish', () => {
      if (req.path === '/healthz') return;
      logger.info('http', { method: req.method, path: req.path, status: res.statusCode, ms: now() - start });
    });
    next();
  });

  const limiter = (windowMs: number, limit: number) =>
    rateLimit({ windowMs, limit, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'rate_limited' } });

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true });
  });

  const asMetadata = authorizationServerMetadata(config);
  const prm = buildOAuthProtectedResourceMetadata({
    oauthMetadata: asMetadata,
    resourceServerUrl: new URL(config.mcpResourceUrl),
    scopesSupported: [MCP_SCOPE],
    resourceName: 'Google Tasks MCP',
    dangerouslyAllowInsecureIssuerUrl: config.allowInsecureHttp,
  });
  // Discovery documents are public; no CORS headers are sent (ChatGPT fetches them server-side).
  const wellKnown = limiter(60_000, 60);
  app.get(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'], wellKnown, (_req, res) => {
    res.json(prm);
  });
  app.get(['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp'], wellKnown, (_req, res) => {
    res.json(asMetadata);
  });

  app.use('/oauth', limiter(60_000, 30));
  app.post('/oauth/authorize', limiter(15 * 60_000, 10));
  app.post('/oauth/register', limiter(60 * 60_000, 20));
  app.use(createOAuthRouter({ config, store, googleOAuth, credentials, logger, now }));

  const verifier = createTokenVerifier(store, credentials, now);
  const auth = requireBearerAuth({
    verifier,
    requiredScopes: [MCP_SCOPE],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(config.mcpResourceUrl)),
    expectedResource: new URL(config.mcpResourceUrl),
  });
  const handler = createMcpHandler((ctx) => buildMcpServer(service, logger, ctx));
  const node = toNodeHandler(handler);
  app.all('/mcp', limiter(60_000, 120), auth, express.json({ limit: '256kb' }), (req, res) => {
    void node(req, res, req.body);
  });

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const status = (err as { status?: unknown })?.status;
    if (typeof status === 'number' && status >= 400 && status < 500) {
      // Body parser errors: their messages can quote request bodies, so only the type is logged.
      logger.warn('Rejected malformed request', { type: (err as { type?: unknown }).type ?? 'unknown', status });
      if (!res.headersSent) res.status(status).json({ error: 'invalid_request' });
      return;
    }
    logger.error('Unhandled error', { error: err instanceof Error ? err.name : 'unknown' });
    if (!res.headersSent) res.status(500).json({ error: 'server_error' });
  });

  return { app, credentials, service };
}
