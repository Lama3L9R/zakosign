
#include "param.h"

static inline bool zako_i8_inrange(char num, char min, char max) {
    return num >= min && num <= max;
}

struct zako_command* zako_new_command(struct zako_command* command, const char* cmd, zako_cmd_handler handler) {
    struct zako_command* new_cmd = ZakoAllocateStruct(zako_command);
    new_cmd->callback = handler;
    new_cmd->command = cmd;

    if (command == NULL) {
        return new_cmd;
    }

    struct zako_command* curr = command->sub_commands;

    if (curr != NULL) {
        while (curr->next != NULL) {
            curr = curr->next;
        }

        curr->next = new_cmd;
    } else {
        command->sub_commands = new_cmd;
    }


    return new_cmd;
}

static void zako_command_free(struct zako_command* root) {
    struct zako_command* curr = root;

    while (curr != NULL) {
        struct zako_command* next = curr->next;

        zako_command_free(curr->sub_commands);

        free(curr);
        curr = next;
    }
}

static void zako_param_free(struct zako_param* root) {
    struct zako_param* curr = root;
    
    while (curr != NULL) {
        struct zako_param* next = curr->next;
        free(curr);
        curr = next;
    }
}

int call_handler(struct zako_command* command, struct zako_param* params, char* flags) {
    if (command == NULL) {
        return -1;
    }

    if (command->callback == NULL) {
        return -1;
    }

    return command->callback(flags, (struct zako_param*) params);
}

int zako_execute(struct zako_command* root, int argc, char* argv[]) {
    if (--argc == 0) {
        int result = call_handler(root, NULL, NULL);
        zako_command_free(root);

        return result;
    }

    struct zako_param* params_root = ZakoAllocateStruct(zako_param);
    struct zako_param* params = params_root;
    char* flags = (char*) zako_allocate_safe(48);
    uint32_t flag_count = 0;
    uint32_t uparam_count = 0;

    struct zako_command* cmd = root;
    bool found_subcommand = false;

    for (uint32_t i = 0; i < argc; i ++) {
        if (zako_strstarts(argv[i], "-")) {
            if (zako_strstarts(argv[i], "--")) {
                params->next = ZakoAllocateStruct(zako_param);
                params->index = -1;
                params->name = &argv[i][2];
                
                if (i + 1 < argc) {
                    params->value = argv[++ i];
                }

                params = params->next;
                continue;
            } else {
                size_t len = strlen(argv[i]) - 1;
                
                if (len <= 0 || len > 48) {
                    continue;
                }

                for (uint8_t j = 0; j < len; j ++) {
                    char fl = argv[i][1 + j];
                    if (zako_i8_inrange(fl, 'A', 'Z')) {
                        flags[fl - 65] = fl;
                    } else if (zako_i8_inrange(fl, 'a', 'z')) {
                        flags[fl - 97 + 24] = fl;
                    } else {
                        continue;
                    }
                }

                continue;
            }
        }

collect_param:
        if (found_subcommand) {
            params->next = ZakoAllocateStruct(zako_param);
            params->index = uparam_count ++;
            params->name = NULL;
            params->value = argv[i];

            params = params->next;

            goto next;
        }

        struct zako_command* curr = cmd->sub_commands;
        found_subcommand = true;

        while (curr != NULL) {
            if (zako_streq(curr->command, argv[i])) {
                cmd = curr;

                found_subcommand = false;
                goto next;
            }

            curr = curr->next;
        }

        goto collect_param;
next:        
        continue;
    }

    int result = call_handler(cmd, params_root, flags);

    /* Free allocated heap memories */
    zako_command_free(root);
    zako_param_free(params_root);
    free(flags);

    return result;
}

bool zako_flag(char* flags, char fl) {
    if (flags == NULL) {
        return false;
    }

    if (zako_i8_inrange(fl, 'A', 'Z')) {
        return flags[fl - 65] != 0;
    } else if (zako_i8_inrange(fl, 'a', 'z')) {
        return flags[fl - 97 + 24] != 0;
    }

    return false;
}

bool zako_flag_param(struct zako_param* params, char* flag) {
    struct zako_param* curr = params;

    while(curr != NULL) {
        if (zako_streq(params->name, flag)) {
            return true;
        }

        curr = curr->next;
    }

    return false;
}

char* zako_param_at(struct zako_param* params, int32_t index) {
    struct zako_param* curr = params;

    while(curr != NULL) {
        if (curr->index == index && curr->value != NULL) {
            return curr->value;
        }

        curr = curr->next;
    }

    return NULL;
}


char* zako_param_named(struct zako_param* params, const char* name) {
    struct zako_param* curr = params;

    while(curr != NULL) {
        if (zako_streq(curr->name, name)) {
            return curr->value;
        }

        curr = curr->next;
    }

    return NULL;
}

uint32_t zako_params_count(struct zako_param* params) {
    if (params == NULL) {
        return 0;
    }

    struct zako_param* curr = params;
    uint32_t count = 0;

    while(curr != NULL) {
        if (curr->value != NULL) {
            count ++;
        }

        curr = curr->next;
    }

    return count;

}