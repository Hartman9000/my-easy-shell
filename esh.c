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
    else {
        int is_executable = find_executable(tokens[0]);
        if (!is_executable) {
            print_command_not_found();
            return 0;
        }
        pid_t pid = fork();
        if (pid < 0) {
            print_execution_error();
            return 0;
        }
        else if (pid == 0) {
            //子进程，执行target
            if (execvp(tokens[0], tokens) == -1) {
                exit(EXIT_FAILURE);
            }
        }
        else {
            //父进程
            int status;
            wait(&status);
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                print_execution_error();
                return 0;
            }
        }
        return 0;
    }
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

        handle_tokens(tokens, token_count);
        
        free(row_prompt);

        // break;
    }
}
