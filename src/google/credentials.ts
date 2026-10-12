import { decrypt, encrypt } from '../crypto.js';
import type { Store } from '../db.js';
import type { Logger } from '../logger.js';
import { GoogleAuthError, type GoogleOAuthClient } from './oauth.js';

const PURPOSE_REFRESH = 'google_refresh_token';
const PURPOSE_ACCESS = 'google_access_token';
const EXPIRY_SKEW_MS = 60_000;

export class NotConnectedError extends Error {
  constructor(message = 'Google account is not connected. Reconnect the app to authorize Google Tasks access again.') {
    super(message);
    this.name = 'NotConnectedError';
  }
}

/**
 * Owns the (single) Google credential. Tokens are only ever decrypted in memory for an outgoing Google API call
 * and are never returned to MCP clients.
 */
export class GoogleCredentials {
  private inflightRefresh: Promise<string> | null = null;

  constructor(
    private readonly store: Store,
    private readonly oauth: GoogleOAuthClient,
    private readonly key: Buffer,
    private readonly logger: Logger,
    private readonly now: () => number = Date.now,
  ) {}

  isConnected(): boolean {
    return this.store.getGoogleAccount() !== undefined;
  }

  ownerSubject(): string | undefined {
    return this.store.getGoogleAccount()?.google_sub;
  }

  save(sub: string, tokens: { access_token: string; expires_in: number; refresh_token?: string; scope: string }): void {
    const existing = this.store.getGoogleAccount();
    let refreshEnc: string;
    if (tokens.refresh_token) {
      refreshEnc = encrypt(tokens.refresh_token, this.key, PURPOSE_REFRESH);
    } else if (existing && existing.google_sub === sub) {
      refreshEnc = existing.refresh_token_enc;
    } else {
      throw new GoogleAuthError('Google did not return a refresh token');
    }
    const now = this.now();
    this.store.upsertGoogleAccount({
      google_sub: sub,
      refresh_token_enc: refreshEnc,
      access_token_enc: encrypt(tokens.access_token, this.key, PURPOSE_ACCESS),
      access_token_expires_at: now + tokens.expires_in * 1000,
      scope: tokens.scope,
      updated_at: now,
    });
  }

  /** Returns a valid Google access token, refreshing it when needed. */
  async getAccessToken(forceRefresh = false): Promise<string> {
    const account = this.store.getGoogleAccount();
    if (!account) throw new NotConnectedError();
    if (!forceRefresh && account.access_token_enc && (account.access_token_expires_at ?? 0) - EXPIRY_SKEW_MS > this.now()) {
      return decrypt(account.access_token_enc, this.key, PURPOSE_ACCESS);
    }
    // Single-flight: concurrent tool calls share one refresh.
    if (!this.inflightRefresh) {
      this.inflightRefresh = this.refresh(account.refresh_token_enc).finally(() => {
        this.inflightRefresh = null;
      });
    }
    return this.inflightRefresh;
  }

  private async refresh(refreshEnc: string): Promise<string> {
    const refreshToken = decrypt(refreshEnc, this.key, PURPOSE_REFRESH);
    try {
      const tokens = await this.oauth.refresh(refreshToken);
      const now = this.now();
      this.store.updateGoogleAccessToken(encrypt(tokens.access_token, this.key, PURPOSE_ACCESS), now + tokens.expires_in * 1000, now);
      return tokens.access_token;
    } catch (err) {
      if (err instanceof GoogleAuthError && err.grantRevoked) {
        // The user revoked access at Google (or the grant expired): invalidate everything locally.
        this.logger.warn('Google grant revoked; disconnecting account');
        this.store.deleteGoogleAccount();
        this.store.revokeAllTokens();
        this.store.audit({ event: 'google_grant_revoked', outcome: 'disconnected' }, this.now());
        throw new NotConnectedError();
      }
      throw err;
    }
  }

  /** Revokes the grant at Google (best effort) and deletes all local credentials and issued MCP tokens. */
  async disconnect(): Promise<{ googleRevoked: boolean; hadAccount: boolean }> {
    const account = this.store.getGoogleAccount();
    let googleRevoked = false;
    if (account) {
      try {
        // Revoking the refresh token also invalidates access tokens derived from it.
        googleRevoked = await this.oauth.revoke(decrypt(account.refresh_token_enc, this.key, PURPOSE_REFRESH));
      } catch {
        googleRevoked = false;
      }
    }
    this.store.deleteGoogleAccount();
    this.store.revokeAllTokens();
    this.store.audit({ event: 'disconnect', outcome: googleRevoked ? 'revoked' : 'local_only' }, this.now());
    return { googleRevoked, hadAccount: account !== undefined };
  }
}
