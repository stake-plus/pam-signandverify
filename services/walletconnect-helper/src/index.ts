import http from "http";

import { loadConfig } from "./config";
import { createServer } from "./server";

async function main() {
  try {
    const config = loadConfig(process.env);
    const app = createServer(config);
    const server = http.createServer(app);

    server.listen(config.port, config.host, () => {
      /* eslint-disable no-console */
      console.log(`WalletConnect helper listening on http://${config.host}:${config.port}`);
      /* eslint-enable no-console */
    });
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

void main();

