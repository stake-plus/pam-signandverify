import http from "http";

import { loadConfig } from "./config";
import { createServer } from "./server";

// Handle unhandled promise rejections to prevent crashes
process.on("unhandledRejection", (reason: unknown, promise: Promise<unknown>) => {
  const errorMessage = reason instanceof Error ? reason.message : String(reason);
  const errorStack = reason instanceof Error ? reason.stack : undefined;
  
  // Log the error but don't crash - WalletConnect proposal expiration is expected
  if (errorMessage.includes("Proposal expired") || errorMessage.includes("proposal")) {
    // This is expected when proposals timeout - just log it
    console.error(`[Unhandled Rejection] Proposal expired: ${errorMessage}`);
    if (errorStack) {
      console.error(errorStack);
    }
  } else {
    // For other errors, log with full details
    console.error("[Unhandled Rejection]", reason);
    if (errorStack) {
      console.error(errorStack);
    }
  }
});

process.on("uncaughtException", (error: Error) => {
  console.error("[Uncaught Exception]", error);
  // Still exit on uncaught exceptions as they indicate serious issues
  process.exit(1);
});

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

