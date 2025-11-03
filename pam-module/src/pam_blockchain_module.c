#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "authorized_wallets.h"
#include "module_config.h"
#include "session_client.h"

static void pam_log(pam_handle_t *pamh, int priority, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    pam_vsyslog(pamh, priority, format, args);
    va_end(args);
}

static void pam_message(pam_handle_t *pamh, int style, const char *format, ...)
{
    if (pamh == NULL || format == NULL) {
        return;
    }

    const struct pam_conv *conv = NULL;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
        return;
    }

    va_list args;
    va_start(args, format);

    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    struct pam_message message;
    const struct pam_message *msg_ptr = &message;
    message.msg_style = style;
    message.msg = buffer;

    struct pam_response *response = NULL;
    conv->conv(1, &msg_ptr, &response, conv->appdata_ptr);
    if (response != NULL) {
        if (response->resp != NULL) {
            free(response->resp);
        }
        free(response);
    }
}

static void pam_info_lines(pam_handle_t *pamh, const char *text)
{
    if (text == NULL) {
        return;
    }

    // Try multiple methods to ensure SSH displays the QR code
    
    // Method 1: Write directly to stderr (SSH forwards this during keyboard-interactive)
    fprintf(stderr, "%s", text);
    fflush(stderr);
    
    // Method 2: Try /dev/tty if available (direct terminal access)
    FILE *tty = fopen("/dev/tty", "w");
    if (tty != NULL) {
        fprintf(tty, "%s", text);
        fflush(tty);
        fclose(tty);
    }

    // Method 3: Send via PAM conversation as text info (for non-SSH contexts)
    const char *cursor = text;
    while (*cursor != '\0') {
        const char *line_end = strchr(cursor, '\n');
        size_t line_length = line_end != NULL ? (size_t)(line_end - cursor) : strlen(cursor);

        char *line = (char *)malloc(line_length + 1);
        if (line == NULL) {
            break;
        }
        memcpy(line, cursor, line_length);
        line[line_length] = '\0';

        pam_message(pamh, PAM_TEXT_INFO, "%s", line);
        free(line);

        if (line_end == NULL) {
            break;
        }
        cursor = line_end + 1;
    }
    
    // Force another flush after PAM messages
    fflush(stderr);
}

static const char *resolve_hostname(pam_handle_t *pamh, char *buffer, size_t buffer_size)
{
    const void *rhost_item = NULL;
    if (pam_get_item(pamh, PAM_RHOST, &rhost_item) == PAM_SUCCESS && rhost_item != NULL) {
        return (const char *)rhost_item;
    }

    if (gethostname(buffer, buffer_size) == 0) {
        buffer[buffer_size - 1] = '\0';
        return buffer;
    }

    return NULL;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;

    struct module_config config;
    char *config_error = NULL;
    if (parse_module_config(&config, argc, argv, &config_error) != 0) {
        pam_log(pamh, LOG_ERR, "pam_blockchain: failed to parse module arguments: %s", config_error != NULL ? config_error : "unknown error");
        free(config_error);
        free_module_config(&config);
        return PAM_SERVICE_ERR;
    }

    const char *user = NULL;
    int pam_status = pam_get_user(pamh, &user, NULL);
    if (pam_status != PAM_SUCCESS || user == NULL || user[0] == '\0') {
        pam_log(pamh, LOG_ERR, "pam_blockchain: unable to determine the user attempting to authenticate");
        free_module_config(&config);
        return PAM_AUTH_ERR;
    }

    char hostname_buffer[256];
    const char *hostname = resolve_hostname(pamh, hostname_buffer, sizeof(hostname_buffer));

    pam_log(pamh, LOG_INFO, "pam_blockchain: initiating wallet authentication for user %s", user);

    struct wallet_session_display display;
    char *session_error = NULL;
    if (wallet_session_start(&config, user, hostname, &display, &session_error) != 0) {
        pam_log(pamh, LOG_ERR, "pam_blockchain: failed to start wallet session: %s", session_error != NULL ? session_error : "unknown error");
        pam_message(pamh, PAM_ERROR_MSG, "Wallet authentication failed: %s", session_error != NULL ? session_error : "Unable to create session");
        free(session_error);
        free_module_config(&config);
        return PAM_AUTH_ERR;
    }

    // Rocky Linux 9.6 SSH suppresses ALL output during keyboard-interactive
    // Write QR code to file and tell user to read it
    char qr_path[256] = {0};
    snprintf(qr_path, sizeof(qr_path), "/tmp/pam-qr-%s.txt", display.session_id);
    
    FILE *f = fopen(qr_path, "w");
    if (f != NULL) {
        fprintf(f, "WalletConnect QR Code for user: %s\n", user);
        fprintf(f, "Session: %s\n\n", display.session_id);
        fprintf(f, "Scan this QR code with your Polkadot wallet:\n\n");
        fprintf(f, "%s\n", display.qr_ascii);
        fprintf(f, "\nWaiting for wallet signature...\n");
        fclose(f);
        chmod(qr_path, 0644);
        
        // Use PAM_ERROR_MSG - SSH on Rocky Linux might display this
        char msg[512];
        snprintf(msg, sizeof(msg), "QR code saved to %s - Read it with: cat %s", qr_path, qr_path);
        pam_message(pamh, PAM_ERROR_MSG, "%s", msg);
        
        // Also write the path to a known location user can check
        FILE *path_file = fopen("/tmp/pam-qr-latest.txt", "w");
        if (path_file) {
            fprintf(path_file, "%s\n", qr_path);
            fclose(path_file);
            chmod("/tmp/pam-qr-latest.txt", 0644);
        }
    } else {
        // File creation failed - clear path so cleanup doesn't try to unlink
        qr_path[0] = '\0';
    }
    
    pam_message(pamh, PAM_TEXT_INFO, "Waiting for wallet signature...");

    struct wallet_session_result result;
    char *wait_error = NULL;
    if (wallet_session_wait(&config, display.session_id, config.timeout_seconds, &result, &wait_error) != 0) {
        pam_log(pamh, LOG_ERR, "pam_blockchain: wallet session wait failed: %s", wait_error != NULL ? wait_error : "unknown error");
        pam_message(pamh, PAM_ERROR_MSG, "Wallet authentication failed: %s", wait_error != NULL ? wait_error : "Session error");
        wallet_session_display_free(&display);
        if (qr_path[0] != '\0') {
            unlink(qr_path);
        }
        unlink("/tmp/pam-qr-latest.txt");
        free(wait_error);
        free_module_config(&config);
        return PAM_AUTH_ERR;
    }

    wallet_session_display_free(&display);

    // Clean up QR file after authentication
    if (qr_path[0] != '\0') {
        unlink(qr_path);
    }
    unlink("/tmp/pam-qr-latest.txt");

    int auth_result = PAM_AUTH_ERR;

    switch (result.status) {
        case WALLET_SESSION_STATUS_APPROVED:
            pam_log(pamh, LOG_INFO, "pam_blockchain: wallet session approved for user %s", user);
            if (result.public_key == NULL || result.public_key[0] == '\0') {
                pam_log(pamh, LOG_ERR, "pam_blockchain: helper did not return a wallet public key");
                pam_message(pamh, PAM_ERROR_MSG, "Wallet authentication failed: missing public key");
                break;
            }

            {
                char *authorization_error = NULL;
                int authorized = is_wallet_authorized(pamh, user, result.public_key, config.chain_name, &authorization_error);
                if (authorized < 0) {
                    pam_log(pamh, LOG_ERR, "pam_blockchain: error checking authorized wallets: %s", authorization_error != NULL ? authorization_error : "unknown error");
                    pam_message(pamh, PAM_ERROR_MSG, "Wallet authentication failed: %s", authorization_error != NULL ? authorization_error : "authorization check error");
                    free(authorization_error);
                    break;
                }

                if (!authorized) {
                    pam_message(pamh, PAM_ERROR_MSG, "Wallet public key is not authorized for this account");
                    break;
                }
            }

            pam_message(pamh, PAM_TEXT_INFO, "Wallet authentication successful.");
            auth_result = PAM_SUCCESS;
            break;
        case WALLET_SESSION_STATUS_TIMEOUT:
            pam_log(pamh, LOG_NOTICE, "pam_blockchain: wallet session timed out for user %s", user);
            pam_message(pamh, PAM_ERROR_MSG, "Wallet authentication timed out.");
            break;
        case WALLET_SESSION_STATUS_REJECTED:
            pam_log(pamh, LOG_NOTICE, "pam_blockchain: wallet session rejected by user %s", user);
            pam_message(pamh, PAM_ERROR_MSG, "Wallet authentication rejected by the wallet.");
            break;
        case WALLET_SESSION_STATUS_ERROR:
        case WALLET_SESSION_STATUS_PENDING:
        default:
            if (result.error_message != NULL) {
                pam_log(pamh, LOG_ERR, "pam_blockchain: wallet session error: %s", result.error_message);
                pam_message(pamh, PAM_ERROR_MSG, "Wallet authentication failed: %s", result.error_message);
            } else {
                pam_log(pamh, LOG_ERR, "pam_blockchain: wallet session ended with an unexpected state");
                pam_message(pamh, PAM_ERROR_MSG, "Wallet authentication failed due to an unexpected state.");
            }
            break;
    }

    wallet_session_result_free(&result);
    free_module_config(&config);
    return auth_result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

