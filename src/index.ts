import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { Store } from './db.js';
import { createLogger } from './logger.js';

const config = loadConfig();
const logger = createLogger(config.logLevel);
const store = new Store(config.databasePath);
const { app } = createApp({ config, store, logger });

const purge = setInterval(() => store.purgeExpired(Date.now()), 15 * 60_000);
purge.unref();

const server = app.listen(config.port, config.host, () => {
  logger.info('Google Tasks MCP server listening', { host: config.host, port: config.port, mcp: config.mcpResourceUrl });
});

const shutdown = () => {
  logger.info('Shutting down');
  server.close(() => {
    store.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
