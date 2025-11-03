#ifndef PAM_BLOCKCHAIN_MODULE_CONFIG_H
#define PAM_BLOCKCHAIN_MODULE_CONFIG_H

#include <stddef.h>

struct module_config {
    const char *helper_path;
    int timeout_seconds;
    const char *chain_name;
};

int parse_module_config(struct module_config *config, int argc, const char **argv, char **error_message);

void free_module_config(struct module_config *config);

#endif /* PAM_BLOCKCHAIN_MODULE_CONFIG_H */

