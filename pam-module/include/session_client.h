#ifndef PAM_BLOCKCHAIN_SESSION_CLIENT_H
#define PAM_BLOCKCHAIN_SESSION_CLIENT_H

#include <stddef.h>

struct module_config;

struct wallet_session_display {
    char *session_id;
    char *uri;
    char *qr_ascii;
    char *message;
};

enum wallet_session_status {
    WALLET_SESSION_STATUS_PENDING = 0,
    WALLET_SESSION_STATUS_APPROVED,
    WALLET_SESSION_STATUS_REJECTED,
    WALLET_SESSION_STATUS_TIMEOUT,
    WALLET_SESSION_STATUS_ERROR
};

struct wallet_session_result {
    enum wallet_session_status status;
    char *public_key;
    char *address;
    char *signature_hex;
    char *error_message;
};

int wallet_session_start(const struct module_config *config, const char *user, const char *hostname, struct wallet_session_display *display, char **error_message);

int wallet_session_wait(const struct module_config *config, const char *session_id, int timeout_seconds, struct wallet_session_result *result, char **error_message);

void wallet_session_display_free(struct wallet_session_display *display);

void wallet_session_result_free(struct wallet_session_result *result);

#endif /* PAM_BLOCKCHAIN_SESSION_CLIENT_H */

