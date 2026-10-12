/**
 * Disconnects the Google account: revokes the grant at Google, deletes the encrypted Google credentials
 * and invalidates every MCP access/refresh token issued by this server.
 *
 * Usage (inside the container): node dist/cli/disconnect.js
 */
import { loadConfig } from '../config.js';
import { Store } from '../db.js';
import { GoogleCredentials } from '../google/credentials.js';
import { GoogleOAuthClient } from '../google/oauth.js';
import { createLogger } from '../logger.js';

const config = loadConfig();
const logger = createLogger(config.logLevel);
const store = new Store(config.databasePath);
const credentials = new GoogleCredentials(store, new GoogleOAuthClient(config), config.encryptionKey, logger);

const result = await credentials.disconnect();
store.close();

if (!result.hadAccount) {
  console.log('No Google account was connected. All MCP tokens issued by this server were invalidated.');
} else if (result.googleRevoked) {
  console.log('Disconnected: Google access revoked, local credentials deleted, all MCP tokens invalidated.');
} else {
  console.log(
    'Local credentials deleted and all MCP tokens invalidated, but Google did not confirm revocation. ' +
      'Remove the app manually at https://myaccount.google.com/connections',
  );
}
