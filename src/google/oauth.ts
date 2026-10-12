import type { Config } from '../config.js';
import { GOOGLE_SCOPES } from '../config.js';

// Fixed Google endpoints. Never derived from user input (SSRF protection).
export const GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
export const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
export const GOOGLE_REVOKE_ENDPOINT = 'https://oauth2.googleapis.com/revoke';
const GOOGLE_ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);

export type FetchFn = typeof fetch;

export class GoogleAuthError extends Error {
  constructor(
    message: string,
    /** True when Google says the grant is no longer valid (revoked/expired) and the account must reconnect. */
    readonly grantRevoked = false,
  ) {
    super(message);
    this.name = 'GoogleAuthError';
  }
}

export interface GoogleTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
  id_token?: string;
}

export class GoogleOAuthClient {
  constructor(
    private readonly config: Pick<Config, 'googleClientId' | 'googleClientSecret' | 'googleRedirectUri'>,
    private readonly fetchFn: FetchFn = fetch,
    private readonly now: () => number = Date.now,
  ) {}

  buildAuthorizationUrl(state: string, codeChallenge: string): string {
    const url = new URL(GOOGLE_AUTH_ENDPOINT);
    url.searchParams.set('client_id', this.config.googleClientId);
    url.searchParams.set('redirect_uri', this.config.googleRedirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', GOOGLE_SCOPES.join(' '));
    url.searchParams.set('access_type', 'offline');
    url.searchParams.set('prompt', 'consent select_account');
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.toString();
  }

  async exchangeCode(code: string, codeVerifier: string): Promise<GoogleTokenResponse> {
    return this.tokenRequest({
      grant_type: 'authorization_code',
      code,
      code_verifier: codeVerifier,
      redirect_uri: this.config.googleRedirectUri,
    });
  }

  async refresh(refreshToken: string): Promise<GoogleTokenResponse> {
    return this.tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken });
  }

  /** Best-effort revocation at Google. Returns false if Google did not confirm. */
  async revoke(token: string): Promise<boolean> {
    try {
      const res = await this.fetchFn(GOOGLE_REVOKE_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }).toString(),
        signal: AbortSignal.timeout(10_000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * Validates the claims of an ID token received directly from Google's token endpoint over TLS
   * (OpenID Connect Core §3.1.3.7 allows skipping signature validation in this case) and returns the stable subject ID.
   */
  subjectFromIdToken(idToken: string): string {
    const parts = idToken.split('.');
    if (parts.length !== 3 || !parts[1]) throw new GoogleAuthError('Malformed ID token');
    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>;
    } catch {
      throw new GoogleAuthError('Malformed ID token');
    }
    if (typeof claims.iss !== 'string' || !GOOGLE_ISSUERS.has(claims.iss)) throw new GoogleAuthError('ID token issuer mismatch');
    const aud = claims.aud;
    const audOk = aud === this.config.googleClientId || (Array.isArray(aud) && aud.includes(this.config.googleClientId));
    if (!audOk) throw new GoogleAuthError('ID token audience mismatch');
    if (typeof claims.exp !== 'number' || claims.exp * 1000 < this.now()) throw new GoogleAuthError('ID token expired');
    if (typeof claims.sub !== 'string' || claims.sub.length === 0) throw new GoogleAuthError('ID token has no subject');
    return claims.sub;
  }

  private async tokenRequest(params: Record<string, string>): Promise<GoogleTokenResponse> {
    let res: Response;
    try {
      res = await this.fetchFn(GOOGLE_TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          ...params,
          client_id: this.config.googleClientId,
          client_secret: this.config.googleClientSecret,
        }).toString(),
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      throw new GoogleAuthError('Could not reach Google token endpoint');
    }
    let body: Record<string, unknown> = {};
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      // ignore - handled below
    }
    if (!res.ok) {
      const err = typeof body.error === 'string' ? body.error : `http_${res.status}`;
      // Only the error code is surfaced; Google's response never contains our secrets but we keep messages minimal.
      throw new GoogleAuthError(`Google token endpoint error: ${err}`, err === 'invalid_grant');
    }
    if (typeof body.access_token !== 'string' || typeof body.expires_in !== 'number') {
      throw new GoogleAuthError('Unexpected Google token response');
    }
    return {
      access_token: body.access_token,
      expires_in: body.expires_in,
      refresh_token: typeof body.refresh_token === 'string' ? body.refresh_token : undefined,
      scope: typeof body.scope === 'string' ? body.scope : '',
      id_token: typeof body.id_token === 'string' ? body.id_token : undefined,
    };
  }
}
