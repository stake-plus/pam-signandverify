#ifndef PAM_BLOCKCHAIN_AUTHORIZED_WALLETS_H
#define PAM_BLOCKCHAIN_AUTHORIZED_WALLETS_H

#include <security/pam_appl.h>

int is_wallet_authorized(pam_handle_t *pamh, const char *user, const char *public_key, const char *chain_name, char **error_message);

#endif /* PAM_BLOCKCHAIN_AUTHORIZED_WALLETS_H */

