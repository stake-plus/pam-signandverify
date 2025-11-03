# PAM Blockchain Wallet Authentication Module

This repository provides a Pluggable Authentication Module (PAM) that defers
interactive logins to a blockchain wallet signer. The initial focus is on
Polkadot-compatible wallets using WalletConnect, with an architecture that can
expand to Ethereum and other WalletConnect ecosystems later on.

## Components

- `pam-module/` – native PAM module implemented in C. During authentication it
  requests a wallet challenge, renders a WalletConnect QR code to the user,
  validates the resulting signature, and compares the recovered public key
  against `~/.ssh/authorized_wallets`.
- `services/walletconnect-helper/` – Node.js helper daemon that brokers
  WalletConnect sessions. It exposes a REST API consumed by the PAM module (via
  the `walletauth-helper` CLI) and performs signature verification with
  `@polkadot/util-crypto`.
- `frontend/` – reserved for the upcoming browser portal that will complement
  the WalletConnect flow.

## Current Flow (Polkadot + WalletConnect)

1. The PAM module invokes `walletauth-helper create-session`. The helper calls
   the daemon, which creates a WalletConnect session, generates a QR code, and
   returns the challenge metadata.
2. The PAM module displays the ASCII QR code in-band through the PAM
   conversation interface.
3. The module then invokes `walletauth-helper await-session` which blocks while
   the daemon waits for the wallet to approve the session and sign the
   challenge message.
4. The daemon verifies the signature using Polkadot crypto primitives and
   returns the recovered public key to the PAM module.
5. The PAM module authorizes the login by checking the public key against the
   user's `~/.ssh/authorized_wallets` file.

## Building the PAM Module

```bash
cmake -S pam-module -B build
cmake --build build
```

The resulting module (`pam_blockchain.so`) will be located under `build/`. Install
it to `/lib/security` (or the appropriate PAM module directory) and update
`/etc/pam.d/sshd` (or the relevant stack) to include a line such as:

```
auth requisite pam_blockchain.so helper=/usr/local/libexec/walletauth-helper
```

## Running the WalletConnect Helper

```bash
cd services/walletconnect-helper
npm install
WALLETCONNECT_PROJECT_ID=<your_project_id> npm run build
WALLETCONNECT_PROJECT_ID=<your_project_id> npm start
```

The service listens on `127.0.0.1:8643` by default. The PAM module communicates
with it via the `walletauth-helper` CLI.

### CLI Usage

The build step above also produces a command-line helper installed as
`walletauth-helper`:

```
# Create a new WalletConnect session and emit ASCII QR code
walletauth-helper create-session --user <username> [--host <hostname>]

# Block until the wallet signs or timeout occurs
walletauth-helper await-session --session <session_id> [--timeout <seconds>]
```

Both commands default to `http://127.0.0.1:8643`; override with
`--base-url http://host:port` or the environment variable
`WALLET_HELPER_BASE_URL`.

## Authorized Wallets File Format

User wallets are authorized via entries in `~/.ssh/authorized_wallets`. Each
line may optionally specify the blockchain namespace:

```
# Allow a single Polkadot wallet
polkadot 0x1234abcd...

# Allow any chain
* 0xfeedbeef...

# Default namespace (Polkadot) when omitted
0x9876dcba...
```

## Next Steps

- Harden the helper daemon (session lifecycle, persistence, error handling).
- Expand signature verification and namespace mapping for Ethereum and other
  WalletConnect-compatible chains.
- Build automated integration tests covering PAM conversation flows.

