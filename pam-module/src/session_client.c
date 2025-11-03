#include "session_client.h"
#include "module_config.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct dynamic_buffer {
    char *data;
    size_t length;
    size_t capacity;
};

static void dynamic_buffer_init(struct dynamic_buffer *buffer)
{
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
}

static int dynamic_buffer_ensure_capacity(struct dynamic_buffer *buffer, size_t additional)
{
    if (buffer->length + additional + 1 <= buffer->capacity) {
        return 0;
    }

    size_t new_capacity = buffer->capacity == 0 ? 256 : buffer->capacity;
    while (new_capacity < buffer->length + additional + 1) {
        new_capacity *= 2;
    }

    char *new_data = (char *)realloc(buffer->data, new_capacity);
    if (new_data == NULL) {
        return -1;
    }

    buffer->data = new_data;
    buffer->capacity = new_capacity;
    return 0;
}

static int dynamic_buffer_append(struct dynamic_buffer *buffer, const char *data, size_t length)
{
    if (dynamic_buffer_ensure_capacity(buffer, length) != 0) {
        return -1;
    }

    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
    return 0;
}

static void dynamic_buffer_free(struct dynamic_buffer *buffer)
{
    if (buffer->data != NULL) {
        free(buffer->data);
        buffer->data = NULL;
    }
    buffer->length = 0;
    buffer->capacity = 0;
}

static char *duplicate_range(const char *start, size_t length)
{
    char *copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, start, length);
    copy[length] = '\0';
    return copy;
}

static char *duplicate_string(const char *value)
{
    if (value == NULL) {
        return NULL;
    }

    size_t len = strlen(value);
    return duplicate_range(value, len);
}

static int run_helper_process(const char *helper_path, char *const argv[], char **output, int *exit_code, char **error_message)
{
    if (output != NULL) {
        *output = NULL;
    }
    if (exit_code != NULL) {
        *exit_code = -1;
    }
    if (error_message != NULL) {
        *error_message = NULL;
    }

    if (helper_path == NULL || argv == NULL) {
        return -1;
    }

    int pipe_fd[2];
    if (pipe(pipe_fd) != 0) {
        if (error_message != NULL) {
            *error_message = duplicate_string("failed to create pipe for helper process");
        }
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        if (error_message != NULL) {
            *error_message = duplicate_string("failed to fork helper process");
        }
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
    }

    if (pid == 0) {
        // Child process
        if (dup2(pipe_fd[1], STDOUT_FILENO) == -1) {
            _exit(127);
        }
        if (dup2(pipe_fd[1], STDERR_FILENO) == -1) {
            _exit(127);
        }
        close(pipe_fd[0]);
        close(pipe_fd[1]);

        execv(helper_path, argv);
        _exit(127);
    }

    // Parent process
    close(pipe_fd[1]);

    struct dynamic_buffer buffer;
    dynamic_buffer_init(&buffer);

    char intermediate[1024];
    ssize_t bytes_read;
    while ((bytes_read = read(pipe_fd[0], intermediate, sizeof(intermediate))) > 0) {
        if (dynamic_buffer_append(&buffer, intermediate, (size_t)bytes_read) != 0) {
            if (error_message != NULL) {
                *error_message = duplicate_string("failed to allocate output buffer for helper process");
            }
            dynamic_buffer_free(&buffer);
            close(pipe_fd[0]);
            waitpid(pid, NULL, 0);
            return -1;
        }
    }

    close(pipe_fd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        if (error_message != NULL) {
            *error_message = duplicate_string("failed to wait for helper process");
        }
        dynamic_buffer_free(&buffer);
        return -1;
    }

    if (exit_code != NULL) {
        if (WIFEXITED(status)) {
            *exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            *exit_code = 128 + WTERMSIG(status);
        } else {
            *exit_code = -1;
        }
    }

    if (output != NULL) {
        *output = buffer.data;
    } else {
        dynamic_buffer_free(&buffer);
    }

    return 0;
}

static int parse_session_display_output(const char *output, struct wallet_session_display *display, char **error_message)
{
    bool in_qr_block = false;
    struct dynamic_buffer qr_buffer;
    dynamic_buffer_init(&qr_buffer);

    const char *cursor = output;
    while (cursor != NULL && *cursor != '\0') {
        const char *line_end = strchr(cursor, '\n');
        size_t line_length = line_end != NULL ? (size_t)(line_end - cursor) : strlen(cursor);

        if (line_length >= 11 && strncmp(cursor, "SESSION_ID=", 11) == 0) {
            if (display->session_id != NULL) {
                free(display->session_id);
            }
            display->session_id = duplicate_range(cursor + 11, line_length - 11);
            if (display->session_id == NULL) {
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate session id");
                }
                dynamic_buffer_free(&qr_buffer);
                return -1;
            }
        } else if (line_length >= 4 && strncmp(cursor, "URI=", 4) == 0) {
            if (display->uri != NULL) {
                free(display->uri);
            }
            display->uri = duplicate_range(cursor + 4, line_length - 4);
            if (display->uri == NULL) {
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate walletconnect uri");
                }
                dynamic_buffer_free(&qr_buffer);
                return -1;
            }
        } else if (line_length >= 8 && strncmp(cursor, "MESSAGE=", 8) == 0) {
            if (display->message != NULL) {
                free(display->message);
            }
            display->message = duplicate_range(cursor + 8, line_length - 8);
            if (display->message == NULL) {
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate message");
                }
                dynamic_buffer_free(&qr_buffer);
                return -1;
            }
        } else if (line_length == 13 && strncmp(cursor, "QR_CODE_BEGIN", 13) == 0) {
            in_qr_block = true;
        } else if (line_length == 11 && strncmp(cursor, "QR_CODE_END", 11) == 0) {
            in_qr_block = false;
        } else if (in_qr_block) {
            if (dynamic_buffer_append(&qr_buffer, cursor, line_length) != 0 || dynamic_buffer_append(&qr_buffer, "\n", 1) != 0) {
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate qr code buffer");
                }
                dynamic_buffer_free(&qr_buffer);
                return -1;
            }
        }

        if (line_end == NULL) {
            break;
        }
        cursor = line_end + 1;
    }

    if (display->session_id == NULL) {
        if (error_message != NULL) {
            *error_message = duplicate_string("helper response missing SESSION_ID");
        }
        dynamic_buffer_free(&qr_buffer);
        return -1;
    }
    if (display->uri == NULL) {
        if (error_message != NULL) {
            *error_message = duplicate_string("helper response missing URI");
        }
        dynamic_buffer_free(&qr_buffer);
        return -1;
    }
    if (qr_buffer.length == 0) {
        if (error_message != NULL) {
            *error_message = duplicate_string("helper response missing QR code block");
        }
        dynamic_buffer_free(&qr_buffer);
        return -1;
    }

    display->qr_ascii = qr_buffer.data;
    return 0;
}

static enum wallet_session_status parse_status_value(const char *value)
{
    if (value == NULL) {
        return WALLET_SESSION_STATUS_ERROR;
    }
    if (strcmp(value, "APPROVED") == 0) {
        return WALLET_SESSION_STATUS_APPROVED;
    }
    if (strcmp(value, "REJECTED") == 0) {
        return WALLET_SESSION_STATUS_REJECTED;
    }
    if (strcmp(value, "TIMEOUT") == 0) {
        return WALLET_SESSION_STATUS_TIMEOUT;
    }
    if (strcmp(value, "PENDING") == 0) {
        return WALLET_SESSION_STATUS_PENDING;
    }
    return WALLET_SESSION_STATUS_ERROR;
}

static int parse_session_result_output(const char *output, struct wallet_session_result *result, char **error_message)
{
    const char *status_value = NULL;
    const char *cursor = output;
    while (cursor != NULL && *cursor != '\0') {
        const char *line_end = strchr(cursor, '\n');
        size_t line_length = line_end != NULL ? (size_t)(line_end - cursor) : strlen(cursor);

        if (line_length >= 7 && strncmp(cursor, "STATUS=", 7) == 0) {
            status_value = duplicate_range(cursor + 7, line_length - 7);
            if (status_value == NULL) {
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate status string");
                }
                return -1;
            }
        } else if (line_length >= 11 && strncmp(cursor, "PUBLIC_KEY=", 11) == 0) {
            char *copy = duplicate_range(cursor + 11, line_length - 11);
            if (copy == NULL) {
                wallet_session_result_free(result);
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate public key");
                }
                return -1;
            }
            result->public_key = copy;
        } else if (line_length >= 8 && strncmp(cursor, "ADDRESS=", 8) == 0) {
            char *copy = duplicate_range(cursor + 8, line_length - 8);
            if (copy == NULL) {
                wallet_session_result_free(result);
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate address");
                }
                return -1;
            }
            result->address = copy;
        } else if (line_length >= 11 && strncmp(cursor, "SIGNATURE=", 11) == 0) {
            char *copy = duplicate_range(cursor + 11, line_length - 11);
            if (copy == NULL) {
                wallet_session_result_free(result);
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate signature");
                }
                return -1;
            }
            result->signature_hex = copy;
        } else if (line_length >= 6 && strncmp(cursor, "ERROR=", 6) == 0) {
            char *copy = duplicate_range(cursor + 6, line_length - 6);
            if (copy == NULL) {
                wallet_session_result_free(result);
                if (error_message != NULL) {
                    *error_message = duplicate_string("failed to allocate error message");
                }
                return -1;
            }
            result->error_message = copy;
        }

        if (line_end == NULL) {
            break;
        }
        cursor = line_end + 1;
    }

    if (status_value == NULL) {
        if (error_message != NULL) {
            *error_message = duplicate_string("helper response missing status field");
        }
        return -1;
    }

    result->status = parse_status_value(status_value);
    free((void *)status_value);

    return 0;
}

int wallet_session_start(const struct module_config *config, const char *user, const char *hostname, struct wallet_session_display *display, char **error_message)
{
    if (display == NULL || config == NULL || config->helper_path == NULL || user == NULL) {
        if (error_message != NULL) {
            *error_message = duplicate_string("invalid arguments to wallet_session_start");
        }
        return -1;
    }

    display->session_id = NULL;
    display->uri = NULL;
    display->qr_ascii = NULL;
    display->message = NULL;

    char timeout_buffer[16];
    snprintf(timeout_buffer, sizeof(timeout_buffer), "%d", config->timeout_seconds);

    char *argv[16];
    size_t idx = 0;
    argv[idx++] = (char *)config->helper_path;
    argv[idx++] = "create-session";
    argv[idx++] = "--user";
    argv[idx++] = (char *)user;
    if (hostname != NULL && hostname[0] != '\0') {
        argv[idx++] = "--host";
        argv[idx++] = (char *)hostname;
    }
    argv[idx++] = "--chain";
    argv[idx++] = (char *)config->chain_name;
    argv[idx++] = "--timeout";
    argv[idx++] = timeout_buffer;
    argv[idx] = NULL;

    char *output = NULL;
    int exit_code = 0;
    int rc = run_helper_process(config->helper_path, argv, &output, &exit_code, error_message);

    if (rc != 0) {
        return -1;
    }

    if (exit_code != 0) {
        if (error_message != NULL) {
            *error_message = duplicate_string(output != NULL ? output : "wallet helper failed");
        }
        free(output);
        return -1;
    }

    int parse_rc = parse_session_display_output(output, display, error_message);
    free(output);
    if (parse_rc != 0) {
        wallet_session_display_free(display);
    }
    return parse_rc;
}

int wallet_session_wait(const struct module_config *config, const char *session_id, int timeout_seconds, struct wallet_session_result *result, char **error_message)
{
    if (result == NULL || config == NULL || config->helper_path == NULL || session_id == NULL) {
        if (error_message != NULL) {
            *error_message = duplicate_string("invalid arguments to wallet_session_wait");
        }
        return -1;
    }

    result->status = WALLET_SESSION_STATUS_ERROR;
    result->public_key = NULL;
    result->address = NULL;
    result->signature_hex = NULL;
    result->error_message = NULL;

    char timeout_buffer[16];
    snprintf(timeout_buffer, sizeof(timeout_buffer), "%d", timeout_seconds);

    char *argv[10];
    size_t idx = 0;
    argv[idx++] = (char *)config->helper_path;
    argv[idx++] = "await-session";
    argv[idx++] = "--session";
    argv[idx++] = (char *)session_id;
    argv[idx++] = "--timeout";
    argv[idx++] = timeout_buffer;
    argv[idx] = NULL;

    char *output = NULL;
    int exit_code = 0;
    int rc = run_helper_process(config->helper_path, argv, &output, &exit_code, error_message);

    if (rc != 0) {
        return -1;
    }

    if (exit_code != 0) {
        if (error_message != NULL) {
            *error_message = duplicate_string(output != NULL ? output : "wallet helper failed");
        }
        free(output);
        return -1;
    }

    int parse_rc = parse_session_result_output(output, result, error_message);
    free(output);
    if (parse_rc != 0) {
        wallet_session_result_free(result);
    }
    return parse_rc;
}

void wallet_session_display_free(struct wallet_session_display *display)
{
    if (display == NULL) {
        return;
    }
    if (display->session_id != NULL) {
        free(display->session_id);
        display->session_id = NULL;
    }
    if (display->uri != NULL) {
        free(display->uri);
        display->uri = NULL;
    }
    if (display->qr_ascii != NULL) {
        free(display->qr_ascii);
        display->qr_ascii = NULL;
    }
    if (display->message != NULL) {
        free(display->message);
        display->message = NULL;
    }
}

void wallet_session_result_free(struct wallet_session_result *result)
{
    if (result == NULL) {
        return;
    }
    if (result->public_key != NULL) {
        free(result->public_key);
        result->public_key = NULL;
    }
    if (result->address != NULL) {
        free(result->address);
        result->address = NULL;
    }
    if (result->signature_hex != NULL) {
        free(result->signature_hex);
        result->signature_hex = NULL;
    }
    if (result->error_message != NULL) {
        free(result->error_message);
        result->error_message = NULL;
    }
}

