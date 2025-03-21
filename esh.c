#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

//
// You should use the following functions to print information
// Do not modify these functions
//

#define MAX_TOKENS 1024
#define MAX_PATH_LEN 1024
#define MAX_RULES 128
#define MAX_PARAMS 8

void print_prompt() {
    printf("esh > ");
    fflush(stdout);
}

void print_invalid_syntax() {
    printf("Invalid Syntax\n");
    fflush(stdout);
}

void print_command_not_found() {
    printf("Command Not Found\n");
    fflush(stdout);
}

void print_execution_error() {
    printf("Execution Error\n");
    fflush(stdout);
}

void print_blocked_syscall(char* syscall_name, int count, ...) {
    va_list args;
    va_start(args, count);
    printf("Blocked Syscall: %s ", syscall_name);
    for (int i = 0; i < count; i++) {
        char* arg = va_arg(args, char*);
        printf("%s ", arg);
    }
    printf("\n");
    fflush(stdout);
}

// 
// You can add your own functions here
//

typedef struct {
    char syscall_name[32];
    int param_count;
    int param_indices[MAX_PARAMS];
    char param_values[MAX_PARAMS][128];
} Rule;

int tokenize(char *prompt, char *tokens[], int max_tokens) {
    int count = 0;
    char *token = strtok(prompt, " ");

    while (token != NULL && count < max_tokens) {
        tokens[count++] = token;
        token = strtok(NULL, " ");
    }
    tokens[count] = NULL;
    return count;
}

void cmd_exit() {
    exit(0);
}

void cmd_cd(char *path) {
    char cwd[MAX_PATH_LEN];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        print_execution_error();
        return;
    }
    if (strcmp(path, "~") == 0) {
        if (chdir(getenv("HOME")) < 0) {
            print_execution_error();
            return;
        }
    }
    else {
        if (chdir(path) < 0) {
            print_execution_error();
            return;
        }
    }
    setenv("OLDPWD", cwd, 1);
    char new_cwd[MAX_PATH_LEN];
    if (getcwd(new_cwd, sizeof(new_cwd)) != NULL) {
        setenv("PWD", new_cwd, 1);
    }
    return;
}

void cmd_export(char *name, char *value) {
    if(setenv(name, value, 1) < 0) {
        print_execution_error();
        return;
    }
}

int find_executable(char *filename) {
    char *slash = strchr(filename, '/');
    if (slash != NULL) {    //存在‘/’，直接查找
        if (access(filename, X_OK) == 0) {
            return 1;
        }
        return 0;
    }
    //不存在‘/’，在PATH中查找
    char *path_env = getenv("PATH");
    char *path = strdup(path_env);
    char *dir = strtok(path, ":");
    char full_path[MAX_PATH_LEN];
    while (dir != NULL) {
        snprintf(full_path, sizeof(full_path), "%s/%s", dir, filename);
        if (access(full_path, X_OK) == 0) {
            free(path);
            return 1;
        }
        dir = strtok(NULL, ":");
    }
    free(path);
    return 0;
}

int check_tokens(char *tokens[]) {
    if (tokens[0] == NULL) {
        print_invalid_syntax();
        return 0;
    }

    int i = 0;

    while (tokens[i] != NULL) {
        if (strcmp(tokens[i], "|") == 0) {
            // 检查管道是否在开头
            if (i == 0) return 0;
            // 检查连续管道
            if (tokens[i + 1] != NULL && (strcmp(tokens[i + 1], "|") == 0 || strcmp(tokens[i + 1], ">") == 0)) return 0;
            // 检查管道后是否有命令
            if (tokens[i + 1] == NULL) return 0;
        }
        else if (strcmp(tokens[i], ">") == 0) {
            // 检查重定向是否在开头
            if (i == 0) return 0;
            // 检查连续重定向
            if (tokens[i + 1] != NULL && (strcmp(tokens[i + 1], "|") == 0 || strcmp(tokens[i + 1], ">") == 0)) return 0;
        }
        else if (strcmp(tokens[i], "||") == 0) return 0;
        else if (strcmp(tokens[i], ">>") == 0) return 0;
        i++;
    }

    // 检查最后一个 token 是否是操作符
    if (i > 0 && (strcmp(tokens[i - 1], "|") == 0 || strcmp(tokens[i - 1], ">") == 0)) {
        print_invalid_syntax();
        return 0;
    }

    return 1; // 语法合法
}

int parse_rules(const char *filename, Rule rules[]) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open rule file\n");
        print_execution_error();
        return -1;
    }

    char line[256];
    int rule_count = 0;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }
        if (strncmp(line, "deny:", 5) != 0) {
            printf("invalid rule format: %s\n", line);
            continue;
        }

        //提取系统调用名和参数
        char *syscall_name = strtok(line + 5, " ");

        Rule rule;
        strncpy(rule.syscall_name, syscall_name, sizeof(rule.syscall_name) - 1);
        rule.param_count = 0;

        char *param_condition = strtok(NULL, " ");
        while (param_condition && rule.param_count < MAX_PARAMS) {
            int idx;
            char value[128];
            if (sscanf(param_condition, "arg%d=%s", &idx, value) == 2) {
                rule.param_indices[rule.param_count] = idx;
                if (value[0] == '"') {
                    strncpy(rule.param_values[rule.param_count], value + 1, sizeof(rule.param_values[0]) - 1);
                    rule.param_values[rule.param_count][strcspn(rule.param_values[rule.param_count], "\"")] = '\0';
                }
                else {
                    strncpy(rule.param_values[rule.param_count], value, sizeof(rule.param_values[0]) - 1);
                }
                rule.param_count ++;
            } else {
                print_execution_error();
                break;
            }
            param_condition = strtok(NULL, " ");
        }
        rules[rule_count++] = rule;
    }
    fclose(file);
    return rule_count;
}

void print_rules(Rule rules[], int count) {
    for (int i = 0; i < count; i++) {
        printf("Rule %d: syscall=%s, param_count=%d\n", i, rules[i].syscall_name, rules[i].param_count);
        for (int j = 0; j < rules[i].param_count; j++) {
            printf("  arg%d=%s\n", rules[i].param_indices[j], rules[i].param_values[j]);
        }
    }
}

int handle_external_cmd(char *tokens[], int token_count) {
    // 计算管道数和子命令数
    int pipe_count = 0;
    for (int i = 0; i < token_count; i++) {
        if (strcmp(tokens[i], "|") == 0) {
            pipe_count++;
        }
    }
    int cmd_count = pipe_count + 1;

    // 创建管道
    int pipefds[pipe_count][2];
    for (int i = 0; i < pipe_count; i++) {
        if (pipe(pipefds[i]) < 0) {
            print_execution_error();
            return 0;
        }
    }

    // 逐一执行命令
    pid_t pids[cmd_count];
    int cmd_idx = 0;
    int cmd_start = 0;
    char *current_tokens[MAX_TOKENS];
    
    for (int i = 0; i <= token_count; i++) {
        if (i == token_count || strcmp(tokens[i], "|") == 0) {
            // 构建当前子命令参数
            int current_token_count = 0;
            int redirect_pos = -1;
            
            // 查找重定向符号位置
            for (int j = cmd_start; j < i; j++) {
                if (strcmp(tokens[j], ">") == 0) {
                    redirect_pos = j;
                    break;
                }
                current_tokens[current_token_count++] = tokens[j];
            }
            current_tokens[current_token_count] = NULL;
            
            // 检查重定向语法
            if (redirect_pos != -1 && (redirect_pos + 1 >= i)) {
                print_invalid_syntax();
                return 0;
            }
            
            // 检查命令是否可执行
            if (current_token_count == 0 || !find_executable(current_tokens[0])) {
                print_command_not_found();
                return 0;
            }
            
            // fork子进程
            pids[cmd_idx] = fork();
            if (pids[cmd_idx] < 0) {
                print_execution_error();
                return 0;
            }
            else if (pids[cmd_idx] == 0) {
                // 子进程
                
                // 设置输入: 如果不是第一个命令，从前一个管道读取
                if (cmd_idx > 0) {
                    dup2(pipefds[cmd_idx - 1][0], STDIN_FILENO);
                }
                
                // 设置输出
                if (redirect_pos != -1) {
                    // 如果有重定向，输出到文件
                    int fd = open(tokens[redirect_pos + 1], O_CREAT | O_WRONLY | O_TRUNC, 0644);
                    if (fd < 0) {
                        print_execution_error();
                        exit(EXIT_FAILURE);
                    }
                    dup2(fd, STDOUT_FILENO);
                    close(fd);
                } else if (cmd_idx < pipe_count) {
                    // 如果没有重定向且不是最后一个命令，输出到管道
                    dup2(pipefds[cmd_idx][1], STDOUT_FILENO);
                }
                
                // 关闭所有管道描述符
                for (int j = 0; j < pipe_count; j++) {
                    close(pipefds[j][0]);
                    close(pipefds[j][1]);
                }
                
                // 执行
                if (execvp(current_tokens[0], current_tokens) < 0) {
                    print_execution_error();
                    exit(EXIT_FAILURE);
                }
            }
            
            // 父进程处理管道
            if (cmd_idx > 0) {
                close(pipefds[cmd_idx - 1][0]); // 关闭前一个管道的读端
            }
            
            if (cmd_idx < pipe_count) {
                close(pipefds[cmd_idx][1]); // 关闭当前管道的写端
            }
            
            cmd_idx++;
            cmd_start = i + 1;
        }
    }
    
    // 父进程关闭所有可能未关闭的管道
    for (int i = 0; i < pipe_count; i++) {
        close(pipefds[i][0]);
        close(pipefds[i][1]);
    }
    
    // 父进程等待子进程返回
    for (int i = 0; i < cmd_count; i++) {
        int status;
        waitpid(pids[i], &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            print_execution_error();
            return 0;
        }
    }
    
    return 0;
}

int handle_tokens(char *tokens[], int token_count) {
    if (strcmp(tokens[0], "exit") == 0) {
        cmd_exit();
    }
    else if (strcmp(tokens[0], "cd") == 0) {
        if (token_count == 1) {
            print_invalid_syntax();
            return 0;
        }
        char *path = tokens[1];
        cmd_cd(path);
        return 0;
    }
    else if (strcmp(tokens[0], "export") == 0) {
        if (token_count == 1) {
            print_invalid_syntax();
            return 0;
        }
        char *equal = strchr(tokens[1], '=');
        char *name = NULL;
        char *value = NULL;
        if (equal == NULL) {
            print_invalid_syntax();
            return 0;
        }
        else {
            size_t name_len = equal - tokens[1];
            name = strndup(tokens[1], name_len);
            value = strdup(equal + 1);
        }
        // printf("name:%s      value:%s\n",name,value);
        cmd_export(name, value);
        free(name);
        free(value);
        return 0;
    }
    return handle_external_cmd(tokens, token_count);
}

char *tokens[MAX_TOKENS];

int main() {
    clearenv();
    char cwd[MAX_PATH_LEN];
    getcwd(cwd, sizeof(cwd));
    setenv("PATH", "/bin", 1);
    setenv("HOME", cwd, 1);
    setenv("PWD", cwd, 1);
    setenv("OLDPWD", cwd, 1);
    setenv("LANG", "en_US.UTF-8", 1);
    setenv("ESH_VERSION", "alpha", 1);

    while(1) {
        print_prompt();

        char *row_prompt = NULL;
        size_t prompt_buffer_size = 0;
        ssize_t read = getline(&row_prompt, &prompt_buffer_size, stdin);
        if (row_prompt[0] == '\n') continue;
        row_prompt[read - 1] = '\0';
        
        int token_count = tokenize(row_prompt, tokens, MAX_TOKENS);

        // printf("总共有 %d 个 token:\n", token_count);
        // for (int i = 0; i < token_count; i++) {
        //     printf("tokens[%d] = \"%s\"\n", i, tokens[i]);
        // }

        if (check_tokens(tokens)) {
            handle_tokens(tokens, token_count);
        }
        else {
            print_invalid_syntax();
        }
        
        free(row_prompt);

        // break;
    }
    // Rule rules[MAX_RULES];
    // int rule_count = parse_rules("rule.txt", rules);
    // if (rule_count < 0) {
    //     fprintf(stderr, "Failed to parse rules.\n");
    //     return 1;
    // }
    // printf("Parsed %d rules:\n", rule_count);
    // print_rules(rules, rule_count);

    // return 0;
}
