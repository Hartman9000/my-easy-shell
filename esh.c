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

int handle_external_cmd(char *tokens[], int token_count) {
    //计算管道数和子命令数
    int pipe_count = 0;
    for (int i = 0; tokens[i] != NULL; i++) {
        if (strcmp(tokens[i], "|") == 0) {
            pipe_count ++;
        }
    }
    int cmd_count = pipe_count + 1;

    //创建管道
    int pipefds[pipe_count][2];
    for (int i = 0; i < pipe_count; i++) {
        if (pipe(pipefds[i]) < 0) {
            print_execution_error();
            return 0;
        }
    }

    //逐一执行命令
    pid_t pids[cmd_count];
    int cmd_idx = 0;
    int cmd_start = 0;
    char *current_tokens[MAX_TOKENS];
    int redirect_fd = -1; //上次重定向的文件描述符
        
    for (int i = 0; i <= token_count; i++) {
        if (i == token_count || strcmp(tokens[i], "|") == 0) {
            // 构建当前子命令参数
            int current_token_count = 0;
            int output_to_file = 0;
            for (int j = cmd_start; j < i; j++) {
                if (strcmp(tokens[j], ">") == 0) {
                    if (tokens[j + 1] == NULL) {
                        print_invalid_syntax();
                        return 0;
                    }
                    output_to_file = 1;
                    break;
                }
                current_tokens[current_token_count++] = tokens[j];
            }
            current_tokens[current_token_count] = NULL;

            //检查命令是否可执行
            if (!find_executable(current_tokens[0])) {
                print_command_not_found();
                return 0;
            }

            //fork子进程
            pids[cmd_idx] = fork();
            if (pids[cmd_idx] < 0) {
                print_execution_error();
                return 0;
            }
            else if (pids[cmd_idx] == 0) {
                //子进程，设置输入
                if (cmd_idx > 0) {
                    if (redirect_fd >= 0) {
                        // 如果上一个命令有重定向，从文件读取
                        dup2(redirect_fd, STDIN_FILENO);
                        close(redirect_fd);
                    } else {
                        // 从前一管道读取
                        dup2(pipefds[cmd_idx - 1][0], STDIN_FILENO);
                    }
                }

                //设置输出
                for (int j = cmd_start; j < i; j++) {
                    if (strcmp(tokens[j], ">") == 0) {
                        //如果当前子命令有重定向，输出需设置为文件
                        redirect_fd = open(tokens[j + 1], O_CREAT | O_WRONLY | O_TRUNC, 0644);
                        if (redirect_fd < 0) {
                            print_execution_error();
                            exit(EXIT_FAILURE);
                        }
                        dup2(redirect_fd, STDOUT_FILENO);
                        close(redirect_fd);
                        break;
                    }
                }
                //如何没有重定向且非最后一个子命令，则输出当前管道
                if (!output_to_file && i < token_count && strcmp(tokens[i], "|") == 0) {
                    dup2(pipefds[cmd_idx][1], STDOUT_FILENO);
                    redirect_fd = -1;
                }

                //关闭所有管道描述符
                for (int j = 0; j < pipe_count; j++) {
                    close(pipefds[j][0]);
                    close(pipefds[j][1]);
                }

                //执行
                if (execvp(current_tokens[0], current_tokens) < 0) {
                    print_execution_error();
                    exit(EXIT_FAILURE);
                }
            }
            
            //父进程关闭管道
            if (cmd_idx > 0 && redirect_fd < 0) {
                close(pipefds[cmd_idx - 1][0]);
            }
            if (i < token_count && !output_to_file) {
                close(pipefds[cmd_idx][1]);
            }

            cmd_idx++;
            cmd_start = i + 1;
            for (int j = i - 1; j >= cmd_start - 1; j--) {
                if (j >= 0 && strcmp(tokens[j], ">") == 0) {
                    redirect_fd = open(tokens[j + 1], O_RDONLY); // 为下一命令准备输入
                    break;
                } else {
                    redirect_fd = -1;
                }
            }
        }
        
    }
    //父进程关闭所有管道
    for (int i = 0;i < pipe_count; i++) {
        close(pipefds[i][0]);
        close(pipefds[i][1]);
    }

    //父进程等待子进程返回
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
}
