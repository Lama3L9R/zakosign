#ifndef ZAKOSIGN_HEADER_PARAM_H
#define ZAKOSIGN_HEADER_PARAM_H

#include "prelude.h"

struct zako_command;
struct zako_param;

typedef int (*zako_cmd_handler)(char* flags, struct zako_param* params);

struct zako_command {
    struct zako_command* next; /* Linked list */

    const char* command;
    zako_cmd_handler callback;
    
    struct zako_command* sub_commands;
};

struct zako_param {
    struct zako_param* next; /* Linked list */

    char* name;
    int32_t index;

    char* value;
};

struct zako_command* zako_new_command(struct zako_command* command, const char* cmd, zako_cmd_handler handler);
int zako_execute(struct zako_command* root, int argc, char* argv[]);

bool zako_flag(char* flags, char flag);
bool zako_flag_param(struct zako_param* params, char* flags);
char* zako_param_at(struct zako_param* params, int32_t index);
char* zako_param_named(struct zako_param* params, const char* name);
uint32_t zako_params_count(struct zako_param* params);

#define ZakoNewCliApp(handler) struct zako_command* root = zako_new_command(NULL, NULL, handler ? (zako_cmd_handler) __zako_cli_root_handler__ : NULL);
#define ZakoCommandHandler(command) static int __zako_cli_##command##_handler__(char* flags, struct zako_param* params)
#define ZakoCommand(base, command) struct zako_command* base##_##command = zako_new_command(base, #command, (zako_cmd_handler) __zako_cli_##base##_##command##_handler__);
#define ZakoFlag(flag) zako_flag(flags, flag)
#define ZakoFlagParam(flag) zako_flag_param(params, flag)
#define ZakoParamAt(index) zako_param_at(params, index)
#define ZakoParam(name) zako_param_named(params, name)
#define ZakoParams() zako_params_count(params)
#define ZakoRunCliApp() return zako_execute(root, argc, &argv[1]);

#endif
