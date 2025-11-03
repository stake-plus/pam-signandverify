import WebSocket from "ws";

// Ensure WalletConnect has a WebSocket implementation and navigator in Node.js environments
if (typeof (globalThis as any).WebSocket === "undefined") {
  (globalThis as any).WebSocket = WebSocket;
}
if (typeof (globalThis as any).navigator === "undefined") {
  (globalThis as any).navigator = { userAgent: "node" };
}

import SignClient from "@walletconnect/sign-client";
import { getSdkError } from "@walletconnect/utils";
import { hexToU8a, stringToU8a, u8aToHex } from "@polkadot/util";
import { signatureVerify, cryptoWaitReady } from "@polkadot/util-crypto";
import QRCode from "qrcode";
import { randomUUID } from "crypto";

import { ServiceConfig } from "./config";
import { SessionRecord, SessionStatus } from "./types";

interface SessionCreationRequest {
  user: string;
  host?: string;
}

interface SessionCreationResponse {
  session: SessionRecord;
}

export interface SessionWaitResult {
  session: SessionRecord;
}

export class WalletConnectService {
  private readonly config: ServiceConfig;
  private clientPromise?: Promise<SignClient>;
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly cryptoReady: Promise<boolean>;

  constructor(config: ServiceConfig) {
    this.config = config;
    this.cryptoReady = cryptoWaitReady();
  }

  async createSession(request: SessionCreationRequest): Promise<SessionCreationResponse> {
    const client = await this.ensureClient();

    const requiredNamespaces = {
      polkadot: {
        chains: this.config.allowedChains,
        methods: ["polkadot_signMessage"],
        events: [] as string[],
      },
    };

    const connection = await client.connect({
      requiredNamespaces,
    });

    if (!connection.uri) {
      throw new Error("WalletConnect client did not provide a pairing URI");
    }

    const qrAscii = await QRCode.toString(connection.uri, { type: "terminal", small: true });
    const challenge = this.buildChallenge(request.user, request.host);
    const chainId = this.config.allowedChains[0];
    const sessionId = randomUUID();

    const session: SessionRecord = {
      id: sessionId,
      user: request.user,
      host: request.host,
      chainId,
      challenge,
      walletConnectUri: connection.uri,
      qrAscii,
      status: "pending",
      createdAt: Date.now(),
      listeners: [],
    };

    this.sessions.set(sessionId, session);

    connection
      .approval()
      .then(async (sessionStruct: { topic: string; namespaces: Record<string, { accounts: string[] }> }) => {
        session.topic = sessionStruct.topic;
        try {
          const namespace = sessionStruct.namespaces.polkadot;
          if (!namespace || namespace.accounts.length === 0) {
            throw new Error("WalletConnect session did not return any Polkadot accounts");
          }

          const account = namespace.accounts[0];
          const [namespaceKey, chain, address] = account.split(":");
          if (!namespaceKey || !chain || !address) {
            throw new Error("Malformed account identifier returned by wallet");
          }

          const resolvedChainId = `${namespaceKey}:${chain}`;
          session.chainId = resolvedChainId;

          const messageBytes = stringToU8a(challenge);
          const requestPayload = {
            method: "polkadot_signMessage",
            params: {
              address,
              message: u8aToHex(messageBytes),
            },
          } as const;

          const signature = await client.request<string>({
            topic: sessionStruct.topic,
            chainId: resolvedChainId,
            request: requestPayload,
          });

          await this.cryptoReady;
          const verification = signatureVerify(messageBytes, hexToU8a(signature), address);
          if (!verification.isValid) {
            this.completeSession(session, "error", {
              error: "Signature verification failed",
            });
            return;
          }

          this.completeSession(session, "approved", {
            address,
            publicKey: u8aToHex(verification.publicKey),
            signature,
          });
        } catch (error: unknown) {
          this.completeSession(session, "error", {
            error: error instanceof Error ? error.message : String(error),
          });
        } finally {
          if (session.topic) {
            try {
              await client.disconnect({ topic: session.topic, reason: getSdkError("USER_DISCONNECTED") });
            } catch {
              // Ignore disconnect errors
            }
          }
        }
      })
      .catch((error: unknown) => {
        this.completeSession(session, "error", {
          error: error instanceof Error ? error.message : String(error),
        });
      });

    return { session };
  }

  async waitForSession(sessionId: string, timeoutSeconds: number): Promise<SessionWaitResult> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error("Session not found");
    }

    if (session.status !== "pending") {
      return { session };
    }

    return new Promise<SessionWaitResult>((resolve) => {
      const timeoutHandle = setTimeout(() => {
        if (session.status === "pending") {
          this.completeSession(session, "timeout", {
            error: "Timed out waiting for wallet confirmation",
          });
        }
      }, timeoutSeconds * 1000);

      session.listeners.push((updated) => {
        clearTimeout(timeoutHandle);
        resolve({ session: updated });
      });
    });
  }

  private completeSession(
    session: SessionRecord,
    status: SessionStatus,
    details: Partial<Pick<SessionRecord, "address" | "publicKey" | "signature" | "error">>
  ) {
    session.status = status;
    if (details.address !== undefined) {
      session.address = details.address;
    }
    if (details.publicKey !== undefined) {
      session.publicKey = details.publicKey;
    }
    if (details.signature !== undefined) {
      session.signature = details.signature;
    }
    if (details.error !== undefined) {
      session.error = details.error;
    }

    const listeners = [...session.listeners];
    session.listeners.length = 0;
    listeners.forEach((listener) => listener(session));

    if (status !== "pending") {
      setTimeout(() => {
        this.sessions.delete(session.id);
      }, this.config.challengeTtlSeconds * 1000);
    }
  }

  private async ensureClient(): Promise<SignClient> {
    if (!this.clientPromise) {
      this.clientPromise = SignClient.init({
        logger: "warn",
        projectId: this.config.projectId,
        relayUrl: this.config.relayUrl,
        metadata: this.config.metadata,
      });
    }

    return this.clientPromise;
  }

  private buildChallenge(user: string, host?: string): string {
    const timestamp = new Date().toISOString();
    return `pam-blockchain login request\nuser=${user}\nhost=${host ?? "localhost"}\ntimestamp=${timestamp}`;
  }
}

