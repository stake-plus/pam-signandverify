import { z } from "zod";

export interface ServiceConfig {
  host: string;
  port: number;
  projectId: string;
  relayUrl?: string;
  challengeTtlSeconds: number;
  allowedChains: string[];
  metadata: {
    name: string;
    description: string;
    url: string;
    icons: string[];
  };
}

const configSchema = z.object({
  host: z.string().optional(),
  port: z.string().optional(),
  projectId: z.string().min(1, "WALLETCONNECT_PROJECT_ID is required"),
  relayUrl: z.string().optional(),
  challengeTtlSeconds: z.string().optional(),
  allowedChains: z.string().optional(),
  serviceUrl: z.string().optional(),
  serviceName: z.string().optional(),
  serviceDescription: z.string().optional(),
  serviceIcon: z.string().optional(),
});

export function loadConfig(env: NodeJS.ProcessEnv): ServiceConfig {
  const parsed = configSchema.safeParse({
    host: env.HOST,
    port: env.PORT,
    projectId: env.WALLETCONNECT_PROJECT_ID,
    relayUrl: env.WALLETCONNECT_RELAY_URL,
    challengeTtlSeconds: env.CHALLENGE_TTL_SECONDS,
    allowedChains: env.WALLETCONNECT_ALLOWED_CHAINS,
    serviceUrl: env.SERVICE_URL,
    serviceName: env.SERVICE_NAME,
    serviceDescription: env.SERVICE_DESCRIPTION,
    serviceIcon: env.SERVICE_ICON,
  });

  if (!parsed.success) {
    const message = parsed.error.errors.map((err) => err.message).join(", ");
    throw new Error(`Configuration error: ${message}`);
  }

  const { serviceIcon, ...values } = parsed.data;

  const port = values.port ? Number(values.port) : 8643;
  if (Number.isNaN(port) || port < 1 || port > 65535) {
    throw new Error("Configuration error: PORT must be a number between 1 and 65535");
  }

  const challengeTtlSeconds = values.challengeTtlSeconds ? Number(values.challengeTtlSeconds) : 180;
  if (Number.isNaN(challengeTtlSeconds) || challengeTtlSeconds < 30 || challengeTtlSeconds > 900) {
    throw new Error("Configuration error: CHALLENGE_TTL_SECONDS must be between 30 and 900");
  }

  const allowedChains = (values.allowedChains ?? "polkadot:91b171bb158e2d3848fa23a9f1c25182")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (allowedChains.length === 0) {
    throw new Error("Configuration error: WALLETCONNECT_ALLOWED_CHAINS yields no chains");
  }

  return {
    host: values.host ?? "127.0.0.1",
    port,
    projectId: values.projectId,
    relayUrl: values.relayUrl,
    challengeTtlSeconds,
    allowedChains,
    metadata: {
      name: values.serviceName ?? "pam-blockchain-auth",
      description: values.serviceDescription ?? "PAM module wallet authentication helper",
      url: values.serviceUrl ?? "https://localhost",
      icons: serviceIcon ? [serviceIcon] : [],
    },
  };
}

