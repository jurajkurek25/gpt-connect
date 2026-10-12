import { z } from 'zod';

/** Google OAuth scopes requested. `openid` only yields the stable account ID (`sub`) used to bind the owner. */
export const GOOGLE_TASKS_SCOPE = 'https://www.googleapis.com/auth/tasks';
export const GOOGLE_SCOPES = ['openid', GOOGLE_TASKS_SCOPE] as const;

/** Scope issued by this server's own authorization server to MCP clients. */
export const MCP_SCOPE = 'tasks';

const DEFAULT_REDIRECT_URIS = 'https://chatgpt.com/connector_platform_oauth_redirect';

const boolFromString = z
  .enum(['true', 'false', '1', '0'])
  .optional()
  .transform((v) => v === 'true' || v === '1');

const EnvSchema = z.object({
  PUBLIC_BASE_URL: z.string().url(),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  GOOGLE_CLIENT_ID: z.string().min(10),
  GOOGLE_CLIENT_SECRET: z.string().min(10),
  TOKEN_ENCRYPTION_KEY: z.string().min(1),
  OWNER_PASSPHRASE: z.string().min(16, 'OWNER_PASSPHRASE must be at least 16 characters'),
  DATABASE_PATH: z.string().default('./data/gtasks-mcp.sqlite'),
  ALLOWED_REDIRECT_URIS: z.string().default(DEFAULT_REDIRECT_URIS),
  TIMEZONE: z.string().default('Europe/Bratislava'),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(1),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  ALLOW_INSECURE_HTTP: boolFromString,
});

export interface Config {
  publicBaseUrl: string;
  publicHost: string;
  host: string;
  port: number;
  mcpResourceUrl: string;
  googleRedirectUri: string;
  googleClientId: string;
  googleClientSecret: string;
  encryptionKey: Buffer;
  ownerPassphrase: string;
  databasePath: string;
  allowedRedirectUris: string[];
  timezone: string;
  trustProxyHops: number;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  allowInsecureHttp: boolean;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    // Only report variable names and messages, never values.
    const problems = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration: ${problems}`);
  }
  const e = parsed.data;

  const base = new URL(e.PUBLIC_BASE_URL);
  if (base.protocol !== 'https:' && !e.ALLOW_INSECURE_HTTP) {
    throw new Error('Invalid configuration: PUBLIC_BASE_URL must use https:// (set ALLOW_INSECURE_HTTP=true only for local testing)');
  }
  if (base.pathname !== '/' || base.search || base.hash) {
    throw new Error('Invalid configuration: PUBLIC_BASE_URL must be an origin without path, query or fragment');
  }
  const publicBaseUrl = base.origin;

  const encryptionKey = Buffer.from(e.TOKEN_ENCRYPTION_KEY, 'base64');
  if (encryptionKey.length !== 32) {
    throw new Error('Invalid configuration: TOKEN_ENCRYPTION_KEY must be 32 random bytes encoded as base64');
  }

  const allowedRedirectUris = e.ALLOWED_REDIRECT_URIS.split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const uri of allowedRedirectUris) {
    const u = new URL(uri);
    if (u.protocol !== 'https:' && !e.ALLOW_INSECURE_HTTP) {
      throw new Error('Invalid configuration: ALLOWED_REDIRECT_URIS entries must use https://');
    }
    if (u.hash) throw new Error('Invalid configuration: ALLOWED_REDIRECT_URIS entries must not contain a fragment');
  }
  if (allowedRedirectUris.length === 0) {
    throw new Error('Invalid configuration: ALLOWED_REDIRECT_URIS must contain at least one URI');
  }

  try {
    new Intl.DateTimeFormat('en-CA', { timeZone: e.TIMEZONE });
  } catch {
    throw new Error('Invalid configuration: TIMEZONE must be an IANA time zone, e.g. Europe/Bratislava');
  }

  return {
    publicBaseUrl,
    publicHost: base.hostname,
    host: e.HOST,
    port: e.PORT,
    mcpResourceUrl: `${publicBaseUrl}/mcp`,
    googleRedirectUri: `${publicBaseUrl}/oauth/google/callback`,
    googleClientId: e.GOOGLE_CLIENT_ID,
    googleClientSecret: e.GOOGLE_CLIENT_SECRET,
    encryptionKey,
    ownerPassphrase: e.OWNER_PASSPHRASE,
    databasePath: e.DATABASE_PATH,
    allowedRedirectUris,
    timezone: e.TIMEZONE,
    trustProxyHops: e.TRUST_PROXY_HOPS,
    logLevel: e.LOG_LEVEL,
    allowInsecureHttp: e.ALLOW_INSECURE_HTTP,
  };
}
