#include "authorized_wallets.h"

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

static char *duplicate_string(const char *value)
{
    if (value == NULL) {
        return NULL;
    }

    size_t length = strlen(value);
    char *copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, length + 1);
    return copy;
}

static char *trim_whitespace(char *input)
{
    if (input == NULL) {
        return NULL;
    }

    while (*input != '\0' && (*input == ' ' || *input == '\t' || *input == '\n' || *input == '\r')) {
        ++input;
    }

    if (*input == '\0') {
        return input;
    }

    char *end = input + strlen(input) - 1;
    while (end > input && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end = '\0';
        --end;
    }

    return input;
}

static int compare_chain_names(const char *line_chain, const char *requested_chain)
{
    if (line_chain == NULL || line_chain[0] == '\0') {
        return requested_chain == NULL ? 0 : strcasecmp(requested_chain, "polkadot");
    }

    if (strcmp(line_chain, "*") == 0) {
        return 0;
    }

    if (requested_chain == NULL) {
        return -1;
    }

    return strcasecmp(line_chain, requested_chain);
}

int is_wallet_authorized(pam_handle_t *pamh, const char *user, const char *public_key, const char *chain_name, char **error_message)
{
    if (error_message != NULL) {
        *error_message = NULL;
    }

    if (user == NULL || public_key == NULL || public_key[0] == '\0') {
        if (error_message != NULL) {
            *error_message = duplicate_string("invalid parameters for wallet authorization check");
        }
        return -1;
    }

    struct passwd *pwd = getpwnam(user);
    if (pwd == NULL) {
        if (error_message != NULL) {
            *error_message = duplicate_string("user account not found");
        }
        return -1;
    }

    char path_buffer[PATH_MAX];
    int written = snprintf(path_buffer, sizeof(path_buffer), "%s/.ssh/authorized_wallets", pwd->pw_dir);
    if (written < 0 || (size_t)written >= sizeof(path_buffer)) {
        if (error_message != NULL) {
            *error_message = duplicate_string("authorized_wallets path is too long");
        }
        return -1;
    }

    FILE *file = fopen(path_buffer, "r");
    if (file == NULL) {
        if (errno == ENOENT) {
            if (pamh != NULL) {
                pam_syslog(pamh, LOG_NOTICE, "authorized_wallets file not found for user %s", user);
            }
            return 0;
        }
        if (error_message != NULL) {
            *error_message = duplicate_string("failed to open authorized_wallets file");
        }
        return -1;
    }

    char *line = NULL;
    size_t line_capacity = 0;
    int is_authorized = 0;

    while (getline(&line, &line_capacity, file) != -1) {
        char *comment = strchr(line, '#');
        if (comment != NULL) {
            *comment = '\0';
        }

        char *trimmed = trim_whitespace(line);
        if (trimmed == NULL || trimmed[0] == '\0') {
            continue;
        }

        char *save_ptr = NULL;
        char *first_token = strtok_r(trimmed, " \t", &save_ptr);
        if (first_token == NULL) {
            continue;
        }

        char *second_token = strtok_r(NULL, " \t", &save_ptr);
        const char *entry_chain = NULL;
        const char *entry_key = NULL;

        if (second_token == NULL) {
            entry_chain = NULL;
            entry_key = first_token;
        } else {
            entry_chain = first_token;
            entry_key = second_token;
        }

        if (compare_chain_names(entry_chain, chain_name) != 0) {
            continue;
        }

        if (strcmp(entry_key, public_key) == 0) {
            is_authorized = 1;
            break;
        }
    }

    free(line);
    fclose(file);

    if (!is_authorized && pamh != NULL) {
        pam_syslog(pamh, LOG_NOTICE, "wallet not authorized for user %s", user);
    }

    return is_authorized;
}

