#include "module_config.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_HELPER_PATH "/usr/local/libexec/pam-blockchain-wallet-helper"
#define DEFAULT_CHAIN_NAME "polkadot"
#define DEFAULT_TIMEOUT_SECONDS 180

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

static int parse_int(const char *input, int *output)
{
    if (input == NULL || output == NULL) {
        return -1;
    }

    char *endptr = NULL;
    long value = strtol(input, &endptr, 10);
    if (endptr == input || *endptr != '\0') {
        return -1;
    }

    if (value < 0 || value > INT_MAX) {
        return -1;
    }

    *output = (int)value;
    return 0;
}

int parse_module_config(struct module_config *config, int argc, const char **argv, char **error_message)
{
    if (config == NULL) {
        return -1;
    }

    config->helper_path = DEFAULT_HELPER_PATH;
    config->timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    config->chain_name = DEFAULT_CHAIN_NAME;

    if (error_message != NULL) {
        *error_message = NULL;
    }

    for (int i = 0; i < argc; ++i) {
        const char *argument = argv[i];
        if (argument == NULL) {
            continue;
        }

        const char *delimiter = strchr(argument, '=');
        if (delimiter == NULL) {
            continue;
        }

        size_t key_length = (size_t)(delimiter - argument);
        const char *value = delimiter + 1;

        if (key_length == 0) {
            continue;
        }

        if (key_length == strlen("helper") && strncmp(argument, "helper", key_length) == 0) {
            char *copy = duplicate_string(value);
            if (copy == NULL) {
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate memory for helper path");
                }
                return -1;
            }
            config->helper_path = copy;
        } else if (key_length == strlen("timeout") && strncmp(argument, "timeout", key_length) == 0) {
            int parsed_value = 0;
            if (parse_int(value, &parsed_value) != 0 || parsed_value <= 0) {
                if (error_message != NULL) {
                    *error_message = duplicate_string("invalid timeout value");
                }
                return -1;
            }
            config->timeout_seconds = parsed_value;
        } else if (key_length == strlen("chain") && strncmp(argument, "chain", key_length) == 0) {
            char *copy = duplicate_string(value);
            if (copy == NULL) {
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate memory for chain name");
                }
                return -1;
            }
            config->chain_name = copy;
        }
    }

    return 0;
}

void free_module_config(struct module_config *config)
{
    if (config == NULL) {
        return;
    }

    if (config->helper_path != NULL && config->helper_path != DEFAULT_HELPER_PATH) {
        free((void *)config->helper_path);
        config->helper_path = DEFAULT_HELPER_PATH;
    }

    if (config->chain_name != NULL && config->chain_name != DEFAULT_CHAIN_NAME) {
        free((void *)config->chain_name);
        config->chain_name = DEFAULT_CHAIN_NAME;
    }
}

