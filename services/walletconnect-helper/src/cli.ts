/* eslint-disable no-console */
import fs from "fs";
import path from "path";
import process from "process";

interface ParsedArgs {
  command: string | null;
  flags: Record<string, string | boolean>;
}

function parseArguments(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv;
  const flags: Record<string, string | boolean> = {};

  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i];
    if (!token.startsWith("--")) {
      continue;
    }

    const key = token.slice(2);
    const next = rest[i + 1];
    if (!next || next.startsWith("--")) {
      flags[key] = true;
    } else {
      flags[key] = next;
      i += 1;
    }
  }

  return { command: command ?? null, flags };
}

function readFlag(flags: Record<string, string | boolean>, key: string): string | undefined {
  const value = flags[key];
  if (typeof value === "boolean") {
    return value ? "true" : undefined;
  }
  return value;
}

function getBaseUrl(flags: Record<string, string | boolean>): string {
  const fromFlag = readFlag(flags, "base-url");
  if (fromFlag) {
    return fromFlag;
  }
  return process.env.WALLET_HELPER_BASE_URL ?? "http://127.0.0.1:8643";
}

const LOG_FILE = "/var/log/pam-blockchain-helper.log";

function logHelperEvent(message: string, meta?: unknown) {
  try {
    const entry = {
      timestamp: new Date().toISOString(),
      message,
      meta,
    };
    fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
    fs.appendFileSync(LOG_FILE, `${JSON.stringify(entry)}\n`);
  } catch {
    // Logging failures should never block authentication.
  }
}

async function handleCreateSession(flags: Record<string, string | boolean>) {
  const baseUrl = getBaseUrl(flags);
  const user = readFlag(flags, "user");
  if (!user) {
    throw new Error("--user flag is required");
  }

  const host = readFlag(flags, "host");

  let response: Response;
  try {
    response = await fetch(`${baseUrl}/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user, host }),
    });
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    logHelperEvent("create-session fetch failed", {
      baseUrl,
      user,
      host,
      error: errMsg,
    });
    throw new Error(`Failed to connect to helper service at ${baseUrl}: ${errMsg}`);
  }

  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as { error?: string };
    logHelperEvent("create-session non-200 response", {
      baseUrl,
      user,
      host,
      status: response.status,
      payload,
    });
    throw new Error(payload.error ?? `Helper service responded with status ${response.status}`);
  }

  const payload = (await response.json()) as {
    sessionId: string;
    walletConnectUri: string;
    qrCode: string;
    challenge: string;
  };

  console.log(`SESSION_ID=${payload.sessionId}`);
  console.log(`URI=${payload.walletConnectUri}`);
  console.log(`MESSAGE=${payload.challenge}`);
  console.log("QR_CODE_BEGIN");
  process.stdout.write(payload.qrCode.endsWith("\n") ? payload.qrCode : `${payload.qrCode}\n`);
  console.log("QR_CODE_END");
}

async function handleAwaitSession(flags: Record<string, string | boolean>) {
  const baseUrl = getBaseUrl(flags);
  const sessionId = readFlag(flags, "session");
  if (!sessionId) {
    throw new Error("--session flag is required");
  }

  const timeoutRaw = readFlag(flags, "timeout");
  let timeoutSeconds: number | undefined;
  if (timeoutRaw !== undefined) {
    const parsed = Number(timeoutRaw);
    if (Number.isNaN(parsed) || parsed <= 0) {
      throw new Error("--timeout must be a positive number of seconds");
    }
    timeoutSeconds = parsed;
  }

  let response: Response;
  try {
    response = await fetch(`${baseUrl}/sessions/${encodeURIComponent(sessionId)}/wait`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ timeoutSeconds }),
    });
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    logHelperEvent("await-session fetch failed", {
      baseUrl,
      sessionId,
      timeoutSeconds,
      error: errMsg,
    });
    throw new Error(`Failed to connect to helper service at ${baseUrl}: ${errMsg}`);
  }

  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as { error?: string };
    logHelperEvent("await-session non-200 response", {
      baseUrl,
      sessionId,
      timeoutSeconds,
      status: response.status,
      payload,
    });
    throw new Error(payload.error ?? `Helper service responded with status ${response.status}`);
  }

  const payload = (await response.json()) as {
    status: string;
    publicKey?: string;
    address?: string;
    signature?: string;
    error?: string;
  };

  console.log(`STATUS=${payload.status.toUpperCase()}`);
  if (payload.publicKey) {
    console.log(`PUBLIC_KEY=${payload.publicKey}`);
  }
  if (payload.address) {
    console.log(`ADDRESS=${payload.address}`);
  }
  if (payload.signature) {
    console.log(`SIGNATURE=${payload.signature}`);
  }
  if (payload.error) {
    console.log(`ERROR=${payload.error}`);
    logHelperEvent("await-session returned error", {
      baseUrl,
      sessionId,
      timeoutSeconds,
      payload,
    });
  }
}

async function main() {
  const { command, flags } = parseArguments(process.argv.slice(2));

  try {
    if (command === "create-session") {
      await handleCreateSession(flags);
    } else if (command === "await-session") {
      await handleAwaitSession(flags);
    } else {
      console.error("Usage: walletauth-helper <create-session|await-session> [options]");
      process.exitCode = 2;
    }
  } catch (error: unknown) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

void main();

