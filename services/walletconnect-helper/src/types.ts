export type SessionStatus = "pending" | "approved" | "rejected" | "timeout" | "error";

export interface SessionRecord {
  id: string;
  user: string;
  host?: string;
  chainId: string;
  challenge: string;
  walletConnectUri: string;
  qrAscii: string;
  status: SessionStatus;
  address?: string;
  publicKey?: string;
  signature?: string;
  error?: string;
  createdAt: number;
  listeners: Array<(session: SessionRecord) => void>;
  topic?: string;
}

