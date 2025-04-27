#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <linux/ptrace.h>
#include <errno.h>
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
#define SYSCALLS_NUM 12
#define EXIT_SUCCESS 0       // 成功退出
#define EXIT_ERROR 1         // 执行错误
#define EXIT_SYNTAX_ERROR 17  // 语法错误
#define EXIT_CMD_NOT_FOUND 127  // 命令未找到
#define EXIT_SANDBOX_BLOCKED 42

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

char *pipe_symbol = "|";
char *redirect_symbol = ">";

typedef struct Rule {
    char syscall_name[32];
    int param_count;
    int param_indices[MAX_PARAMS];
    char param_values[MAX_PARAMS][128];
    struct Rule *next;
} Rule;

Rule *head_rule = NULL;

typedef enum {
    ARG_TYPE_OTHER,
    ARG_TYPE_INT,
    ARG_TYPE_STRING,
    ARG_TYPE_POINTER
} arg_type_t;

typedef struct {
    char name[32];
    int syscall_number; 
    arg_type_t arg_types[6];
} syscall_info_t;

// 预定义支持的系统调用信息
syscall_info_t syscall_infos[SYSCALLS_NUM] = {
    {"read",        0, {ARG_TYPE_INT, ARG_TYPE_POINTER, ARG_TYPE_INT}},       // fd, buf, count
    {"write",       1, {ARG_TYPE_INT, ARG_TYPE_STRING, ARG_TYPE_INT}},       // fd, buf, count
    {"open",        2, {ARG_TYPE_STRING, ARG_TYPE_INT, ARG_TYPE_INT}},        // filename, flags, mode
    {"mmap",        9, {ARG_TYPE_POINTER, ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_INT}}, // addr, length, prot, flags, fd, offset
    {"pipe",       22, {ARG_TYPE_POINTER}},                                   // filedes
    {"sched_yield",24, {0}},                                                  // 无参数
    {"dup",        32, {ARG_TYPE_INT}},                                       // oldfd
    {"clone",      56, {ARG_TYPE_INT, ARG_TYPE_POINTER, ARG_TYPE_POINTER, ARG_TYPE_POINTER, ARG_TYPE_INT}}, // flags, stack, parent_tid, child_tid, tls
    {"fork",       57, {0}},                                                  // 无参数
    {"execve",     59, {ARG_TYPE_STRING, ARG_TYPE_POINTER, ARG_TYPE_POINTER}}, // filename, argv, envp
    {"mkdir",      83, {ARG_TYPE_STRING, ARG_TYPE_INT}},                      // pathname, mode
    {"chmod",      90, {ARG_TYPE_STRING, ARG_TYPE_INT}}                       // pathname, mode
};

int tokenize(char *prompt, char *tokens[], int max_tokens) {
    int count = 0;
    int in_quotes = 0;  // 是否在引号内
    char *start = prompt;
    char *p = prompt;

    while (*p != '\0' && count < max_tokens) {
        // 处理引号
        if (*p == '"') {
            if (in_quotes) {
                // 引号结束
                *p = '\0';  // 截断字符串
                if (p > start) {
                    tokens[count++] = start + 1;  // +1 跳过开始的引号
                }
                in_quotes = 0;
                start = p + 1;  // 下一个token从引号后开始
            } else {
                // 引号开始
                if (p > start) {
                    // 处理引号前的部分
                    *p = '\0';
                    
                    // 分割非引号部分的空格分隔的token
                    char *token = strtok(start, " ");
                    while (token != NULL && count < max_tokens) {
                        tokens[count++] = token;
                        token = strtok(NULL, " ");
                    }
                }
                in_quotes = 1;
                start = p;  // 记住引号的位置
            }
        } else if (!in_quotes && (*p == '|' || *p == '>')) {
            // 遇到管道符或重定向符（在引号外）
            char sym = *p;
            if (p > start) {
                // 保存符号前的token
                *p = '\0';
                if (*start != '\0') {
                    // 处理符号前可能有多个以空格分隔的token
                    char *token = strtok(start, " ");
                    while (token != NULL && count < max_tokens) {
                        tokens[count++] = token;
                        token = strtok(NULL, " ");
                    }
                }
            }
            
            if (sym == '|') tokens[count++] = pipe_symbol;
            else if (sym == '>') tokens[count++] = redirect_symbol;
            
            start = p + 1;
        } else if (*p == ' ' && !in_quotes) {
            // 不在引号内的空格，标记为字符串结束
            *p = '\0';
            
            // 添加非空token
            if (p > start && *start != '\0') {
                tokens[count++] = start;
            }
            
            start = p + 1;  // 下一个token从空格后开始
        }
        
        p++;
    }
    
    // 处理最后一个token
    if (!in_quotes && *start != '\0' && count < max_tokens) {
        // 最后一段不在引号内，可能有多个以空格分隔的token
        char *token = strtok(start, " ");
        while (token != NULL && count < max_tokens) {
            tokens[count++] = token;
            token = strtok(NULL, " ");
        }
    } else if (in_quotes && count < max_tokens) {
        // 未闭合的引号，当作普通字符串处理
        tokens[count++] = start + 1;
    }

    // 确保tokens数组以NULL结尾
    if (count < max_tokens) {
        tokens[count] = NULL;
    }
    
    return count;
}

void cmd_exit() {
    exit(0);
}

void cmd_cd(char *path, int in_child) {
    char cwd[MAX_PATH_LEN];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        if (in_child) exit(EXIT_ERROR);
        print_execution_error();
        return;
    }
    
    // 处理 ~ 开头的路径
    if (path[0] == '~') {
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s%s", getenv("HOME"), path + 1);
        if (chdir(full_path) < 0) {
            if (in_child) exit(EXIT_ERROR);
            print_execution_error();
            return;
        }
    }
    else if (chdir(path) < 0) {
        if (in_child) exit(EXIT_ERROR);
        print_execution_error();
        return;
    }
    
    setenv("OLDPWD", cwd, 1);
    char new_cwd[MAX_PATH_LEN];
    if (getcwd(new_cwd, sizeof(new_cwd)) != NULL) {
        setenv("PWD", new_cwd, 1);
    }

    if (in_child) exit(EXIT_SUCCESS);
}

int find_executable(char *filename) {
    if (strlen(filename) == 0) return 0;
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

Rule *parse_rules(const char *filename, Rule **head_rule) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open rule file");
        return NULL;  // 返回NULL但不输出错误信息
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        // 去除换行符
        line[strcspn(line, "\n")] = '\0';
        
        // 忽略空行和注释行
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }
        
        // 处理行末注释
        char *comment_pos = strchr(line, '#');
        if (comment_pos != NULL) {
            *comment_pos = '\0';  // 删除注释部分
        }
        
        // 去除末尾空白字符
        int len = strlen(line);
        while (len > 0 && isspace(line[len-1])) {
            line[--len] = '\0';
        }
        
        // 检查是否以 deny: 开头
        if (strncmp(line, "deny:", 5) != 0) {
            continue;  // 忽略非法行，不输出错误
        }

        // 分配规则结构体
        Rule *rule = (Rule *)malloc(sizeof(Rule));
        if (!rule) {
            continue;  // 内存分配失败
        }
        memset(rule, 0, sizeof(Rule));  // 初始化为零
        
        // 提取系统调用名
        char *pos = line + 5;
        while (*pos && isspace(*pos)) pos++;  // 跳过前导空格
        
        char *syscall_end = pos;
        while (*syscall_end && !isspace(*syscall_end)) syscall_end++;
        
        int syscall_len = syscall_end - pos;
        if (syscall_len == 0 || syscall_len >= sizeof(rule->syscall_name)) {
            free(rule);
            continue;
        }
        
        strncpy(rule->syscall_name, pos, syscall_len);
        rule->syscall_name[syscall_len] = '\0';
        
        // 解析参数
        pos = syscall_end;
        while (*pos && rule->param_count < MAX_PARAMS) {
            // 跳过空格
            while (*pos && isspace(*pos)) pos++;
            if (!*pos) break;
            
            // 检查是否是arg开头
            if (strncmp(pos, "arg", 3) != 0) {
                break;  // 不是arg开头，结束解析
            }
            
            pos += 3;  // 跳过"arg"
            
            // 获取参数索引
            char *endptr;
            int idx = strtol(pos, &endptr, 10);
            if (endptr == pos || *endptr != '=') {
                break;  // 参数索引解析失败
            }
            
            rule->param_indices[rule->param_count] = idx;
            pos = endptr + 1;  // 跳过等号
            
            // 处理参数值
            if (*pos == '"') {  // 双引号开始的字符串
                pos++;  // 跳过开始引号
                char *value_start = pos;
                
                // 寻找结束引号
                while (*pos && *pos != '"') pos++;
                
                if (!*pos) {  // 没找到结束引号
                    break;
                }
                
                int value_len = pos - value_start;
                if (value_len >= sizeof(rule->param_values[0])) {
                    value_len = sizeof(rule->param_values[0]) - 1;
                }
                
                strncpy(rule->param_values[rule->param_count], value_start, value_len);
                rule->param_values[rule->param_count][value_len] = '\0';
                pos++;  // 跳过结束引号
            } else {  // 非引号包围的值
                char *value_start = pos;
                
                // 寻找空格或结束
                while (*pos && !isspace(*pos)) pos++;
                
                int value_len = pos - value_start;
                if (value_len >= sizeof(rule->param_values[0])) {
                    value_len = sizeof(rule->param_values[0]) - 1;
                }
                
                strncpy(rule->param_values[rule->param_count], value_start, value_len);
                rule->param_values[rule->param_count][value_len] = '\0';
            }
            
            rule->param_count++;
        }
        
        // 将规则添加到链表
        if (*head_rule == NULL) {
            *head_rule = rule;
            rule->next = NULL;
        } else {
            rule->next = *head_rule;
            *head_rule = rule;
        }
    }
    fclose(file);
    return *head_rule;
}

void print_rules(Rule *head_rule) {
    while (head_rule != NULL) {
        printf("syscall=%s, param_count=%d\n",head_rule->syscall_name, head_rule->param_count);
        for (int j = 0; j < head_rule->param_count; j++) {
            printf("  arg%d=%s\n", head_rule->param_indices[j], head_rule->param_values[j]);
        }
        head_rule = head_rule->next;
    }
}

void free_rules(Rule **head_rule) {
    while (*head_rule != NULL) {
        Rule *temp = *head_rule;
        *head_rule = (*head_rule)->next;
        free(temp);
    }
}

// 从进程内存中读取字符串
char* read_string_from_process(pid_t pid, unsigned long addr) {
    char *str = malloc(4096); // 分配足够大的缓冲区
    if (!str) return NULL;
    
    size_t i = 0;
    long data;
    
    while (i < 4095) {
        errno = 0;
        data = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (errno != 0) {
            free(str);
            return NULL;
        }
        
        memcpy(str + i, &data, sizeof(long));
        
        // 检查是否到达字符串结尾
        int found_null = 0;
        for (size_t j = 0; j < sizeof(long); j++) {
            if (str[i + j] == '\0') {
                found_null = 1;
                break;
            }
        }
        
        if (found_null) break;
        i += sizeof(long);
    }
    
    str[4095] = '\0'; // 确保字符串结束
    return str;
}

int match_rule(pid_t child_pid, Rule *rule, long syscall_num, struct user_regs_struct *regs) {
    // 找到系统调用索引
    int syscall_index = -1;
    for (int i = 0; i < SYSCALLS_NUM; i++) {
        if (syscall_infos[i].syscall_number == syscall_num && 
            strcmp(syscall_infos[i].name, rule->syscall_name) == 0) {
            syscall_index = i;
            break;
        }
    }
    
    if (syscall_index == -1) return 0;
    
    // 无参数条件，认为匹配成功
    if (rule->param_count == 0) {
        return 1;
    }
    
    // 获取参数值
    unsigned long long args[6] = {
        regs->rdi, regs->rsi, regs->rdx, 
        regs->r10, regs->r8, regs->r9
    };
    
    // 检查每个参数条件，必须全部匹配
    for (int i = 0; i < rule->param_count; i++) {
        //遍历每个参数
        int param_idx = rule->param_indices[i];
        if (param_idx < 0 || param_idx >= 6) continue;
        
        arg_type_t arg_type = syscall_infos[syscall_index].arg_types[param_idx];
        int param_matched = 0; // 标记当前参数是否匹配
        
        switch (arg_type) {
            case ARG_TYPE_STRING: {
                // 对于字符串参数，从进程内存中读取并比较
                char *param_str = read_string_from_process(child_pid, args[param_idx]);
                if (param_str) {
                    if (strcmp(param_str, rule->param_values[i]) == 0) {
                        param_matched = 1; // 字符串匹配
                    }
                    free(param_str);
                }
                break;
            }
            case ARG_TYPE_INT: {
                // 对于整数参数，转换并比较
                long param_value;
                if (sscanf(rule->param_values[i], "%ld", &param_value) == 1) {
                    if (args[param_idx] == (unsigned long long)param_value) {
                        param_matched = 1; // 整数匹配
                    }
                }
                break;
            }
            case ARG_TYPE_POINTER:
            case ARG_TYPE_OTHER: {
                // 对于指针和其他类型，可以比较十六进制值或十进制值
                unsigned long long param_value;
                // 检查是否是十六进制格式 (0x开头)
                if (strncmp(rule->param_values[i], "0x", 2) == 0) {
                    if (sscanf(rule->param_values[i] + 2, "%llx", &param_value) == 1) {
                        if (args[param_idx] == param_value) {
                            param_matched = 1; // 十六进制匹配
                        }
                    }
                }
                // 也尝试解析为十进制
                else if (sscanf(rule->param_values[i], "%lld", &param_value) == 1) {
                    if (args[param_idx] == param_value) {
                        param_matched = 1; // 十进制匹配
                    }
                }
                break;
            }
        }
        
        // 如果任一参数不匹配，则整个规则不匹配
        if (!param_matched) {
            return 0;
        }
    }
    
    // 所有参数都匹配，返回1
    return 1;
}

// 将参数值转换为适当的字符串形式
char* format_param_value(pid_t child_pid, unsigned long long arg_value, arg_type_t arg_type) {
    char* result = malloc(256); // 足够大的缓冲区
    if (!result) return NULL;
    
    switch (arg_type) {
        case ARG_TYPE_STRING: {
            // 字符串类型: 从进程内存读取并添加引号
            char* str = read_string_from_process(child_pid, arg_value);
            if (str) {
                snprintf(result, 255, "\"%s\"", str);
                free(str);
            } else {
                snprintf(result, 255, "\"\"");
            }
            break;
        }
        case ARG_TYPE_INT:
            // 整数类型: 直接转换为字符串
            snprintf(result, 255, "%lld", arg_value);
            break;
        case ARG_TYPE_POINTER:
        case ARG_TYPE_OTHER:
        default:
            // 指针和其他类型: 转换为十六进制，前缀0x
            snprintf(result, 255, "0x%llx", arg_value);
            break;
    }
    
    return result;
}

// 在系统调用被阻止时收集并格式化参数
void handle_blocked_syscall(pid_t child_pid, Rule *rule, long syscall_num, struct user_regs_struct *regs) {
    // 找到系统调用索引
    int syscall_index = -1;
    for (int i = 0; i < SYSCALLS_NUM; i++) {
        if (syscall_infos[i].syscall_number == syscall_num) {
            syscall_index = i;
            break;
        }
    }
    
    if (syscall_index == -1) return;
    
    // 获取参数值
    unsigned long long args[6] = {
        regs->rdi, regs->rsi, regs->rdx, 
        regs->r10, regs->r8, regs->r9
    };
    
    // 确定要收集的参数个数 (rule->param_count或最多6个)
    int param_count = 0;
    while (syscall_infos[syscall_index].arg_types[param_count] != 0) param_count++;
    
    // 准备参数字符串数组
    char *param_strings[MAX_PARAMS] = {NULL};
    
    // 收集参数值并格式化
    if (param_count > 0) {
        for (int i = 0; i < param_count; i++) {
                param_strings[i] = format_param_value(child_pid, args[i], syscall_infos[syscall_index].arg_types[i]);
        }
    }
    
    // 打印阻止的系统调用信息
    print_blocked_syscall(rule->syscall_name, param_count,
                         param_count > 0 ? param_strings[0] : NULL,
                         param_count > 1 ? param_strings[1] : NULL,
                         param_count > 2 ? param_strings[2] : NULL,
                         param_count > 3 ? param_strings[3] : NULL,
                         param_count > 4 ? param_strings[4] : NULL,
                         param_count > 5 ? param_strings[5] : NULL,
                         param_count > 6 ? param_strings[6] : NULL,
                         param_count > 7 ? param_strings[7] : NULL);
    
    // 释放参数字符串
    for (int i = 0; i < param_count; i++) {
        if (param_strings[i]) free(param_strings[i]);
    }
}

void show_syscall(int syscall_idx,pid_t child_pid, struct user_regs_struct *regs) {
    if (syscall_idx >= 0) {
        // 获取系统调用的参数值
        unsigned long long args[6] = {
            regs->rdi, regs->rsi, regs->rdx, 
            regs->r10, regs->r8, regs->r9
        };
        // 如果系统调用被支持，打印调试信息
        printf("Detected supported syscall: %s\n", syscall_infos[syscall_idx].name);
        // 打印系统调用的参数
        for (int i = 0; i < 6; i++) {
            arg_type_t arg_type = syscall_infos[syscall_idx].arg_types[i];
            switch (arg_type) {
                case ARG_TYPE_STRING: {
                    char *param_str = read_string_from_process(child_pid, args[i]);
                    printf("  arg%d: \"%s\" (string)\n", i, param_str ? param_str : "(null)");
                    free(param_str);
                    break;
                }
                case ARG_TYPE_INT:
                    printf("  arg%d: %lld (int)\n", i, args[i]);
                    break;
                case ARG_TYPE_POINTER:
                    printf("  arg%d: 0x%llx (pointer)\n", i, args[i]);
                    break;
                case ARG_TYPE_OTHER:
                default:
                    printf("  arg%d: 0x%llx (other/unknown)\n", i, args[i]);
                    break;
            }
        }
    }
}

void trace_child(pid_t child_pid, Rule *head_rule) {
    int status;
    struct user_regs_struct regs;
    int in_syscall = 0; // 跟踪是否正在系统调用中

    while (1) {
        waitpid(child_pid, &status, 0);
        
        if (WIFEXITED(status)) {
            break; // 子进程已退出
        }
        
        if (!WIFSTOPPED(status)) {
            continue; // 不是因为停止信号而停止的
        }
        
        // 检查是否是 SIGSTOP 导致的停顿
        if (WSTOPSIG(status) == SIGSTOP) {
            ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD); // 设置TRACESYSGOOD选项
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
            continue;
        }

        // 处理系统调用
        if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            if (!in_syscall) {
                // 系统调用入口点
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                long syscall_num = regs.orig_rax;
                
                // 检查系统调用是否存在于我们支持的列表中
                int syscall_idx = -1; //当前系统调用在调用表中的索引
                for (int i = 0; i < SYSCALLS_NUM; i++) {
                    if (syscall_infos[i].syscall_number == syscall_num) {
                        syscall_idx = i;
                        break;
                    }
                }
    
                // 调试内容
                // if (syscall_idx >=0) {
                //     printf("in_syscall:%d\n",in_syscall);
                //     printf("WSTOPSIG(status):%u\n", WSTOPSIG(status));
                //     printf("SIGTRAP | 0x80:%u\n", SIGTRAP | 0x80);
                //     show_syscall(syscall_idx, child_pid, &regs);
                // }
                
                if (syscall_idx >= 0) {
                    // 检查系统调用是否被规则禁止
                    Rule *rule = head_rule;
                    while (rule != NULL) {
                        // 检查系统调用名称是否与当前规则匹配
                        if (strcmp(syscall_infos[syscall_idx].name, rule->syscall_name) == 0) {
                            // 如果没有参数条件或参数条件匹配，则阻止系统调用
                            if (rule->param_count == 0 || match_rule(child_pid, rule, syscall_num, &regs)) {
                                // 处理并打印被阻止的系统调用信息
                                handle_blocked_syscall(child_pid, rule, syscall_num, &regs);
                                
                                // 修改系统调用返回结果为错误
                                regs.orig_rax = -1;
                                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                                
                                // 设置退出状态码
                                regs.rax = EXIT_SANDBOX_BLOCKED;
                                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                                
                                // 继续执行让子进程自己退出
                                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
                                return;
                            }
                        }
                        rule = rule->next;
                    }
                }
            }
            in_syscall = in_syscall == 1 ? 0 : 1;
        }
        
        
        // 继续执行直到下一个系统调用
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    }
}

int is_builtin_cmd(char *cmd) {
    return (strcmp(cmd, "exit") == 0 || 
            strcmp(cmd, "cd") == 0 || 
            strcmp(cmd, "export") == 0);
}

// 执行内置命令的通用函数，可同时用于主进程和子进程
// in_child: 1表示在子进程中执行，0表示在主进程中执行
int exec_builtin_cmd(char *tokens[], int token_count, int in_child) {
    if (strcmp(tokens[0], "exit") == 0) {
        if (in_child) {
            exit(EXIT_SUCCESS);  // 子进程直接退出
        } else {
            cmd_exit();  // 主进程调用cmd_exit
        }
        return 1;
    }
    else if (strcmp(tokens[0], "cd") == 0) {
        if (token_count == 1) {
            if (in_child) exit(EXIT_SYNTAX_ERROR);
            print_invalid_syntax();
            return 0;
        }
        else if (token_count > 2) {
            if (in_child) exit(EXIT_SYNTAX_ERROR);
            print_invalid_syntax();
            return 0;
        }
        char *path = tokens[1];
        cmd_cd(path, in_child);

        if (in_child) exit(EXIT_SUCCESS);
        return 1;
    }
    else if (strcmp(tokens[0], "export") == 0) {
        if (token_count == 1) {
            if (in_child) exit(EXIT_SYNTAX_ERROR);
            print_invalid_syntax();
            return 0;
        }
        char *equal = strchr(tokens[1], '=');
        char *name = NULL;
        char *value = NULL;
        if (equal == NULL) {
            if (in_child) exit(EXIT_SYNTAX_ERROR);
            print_invalid_syntax();
            return 0;
        }
        else {
            size_t name_len = equal - tokens[1];
            name = strndup(tokens[1], name_len);
            value = strdup(equal + 1);
        }
        if(setenv(name, value, 1) < 0) {
            if (in_child) exit(EXIT_ERROR);
            print_execution_error();
            return 0;
        }
        free(name);
        free(value);
        if (in_child) exit(EXIT_SUCCESS);
        return 1;
    }
    
    // 不是内置命令
    if (in_child) exit(EXIT_CMD_NOT_FOUND);  // 子进程出错退出
    return 0;               // 主进程返回0表示不是内置命令
}

int handle_cmd(char *tokens[], int token_count, Rule *head_rule) {
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
    int prev_cmd_failed = 0;
    
    for (int i = 0; i <= token_count; i++) {
        if (i == token_count || strcmp(tokens[i], "|") == 0) {
            // 构建当前子命令参数
            int current_token_count = 0;
            int redirect_positions[MAX_TOKENS]; // 存储所有重定向符号位置
            int redirect_count = 0;

            // 查找所有重定向符号位置
            for (int j = cmd_start; j < i; j++) {
                if (strcmp(tokens[j], ">") == 0) {
                    redirect_positions[redirect_count++] = j;
                } else if (redirect_count == 0) {
                    // 只添加重定向符号前的token作为命令参数
                    current_tokens[current_token_count++] = tokens[j];
                }
            }
            current_tokens[current_token_count] = NULL;
            
            // 检查重定向语法
            int invalid_redirect = 0;
            for (int j = 0; j < redirect_count; j++) {
                if (redirect_positions[j] + 1 >= i || (j > 0 && redirect_positions[j] != redirect_positions[j-1] + 2)) {
                    invalid_redirect = 1;
                    break;
                }
            }
            if (invalid_redirect) {
                print_invalid_syntax();
                prev_cmd_failed = 1;
                cmd_idx++;
                cmd_start = i + 1;
                continue;
            }

            int is_builtin = is_builtin_cmd(current_tokens[0]);
            
            // fork子进程
            pids[cmd_idx] = fork();
            if (pids[cmd_idx] < 0) {
                print_execution_error();
                prev_cmd_failed = 1;
                cmd_idx++;
                cmd_start = i + 1;
                continue;
            }
            else if (pids[cmd_idx] == 0) {
                // 子进程

                //启用ptrace
                if (head_rule != NULL && !is_builtin) {
                    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
                    kill(getpid(), SIGSTOP);
                }
                
                // 设置输入: 如果前一个命令失败，关闭标准输入，否则从管道输入
                if (cmd_idx > 0) {
                    if (prev_cmd_failed) {
                        close(STDIN_FILENO);
                        open("/dev/null", O_RDONLY);
                    }
                    else {
                        dup2(pipefds[cmd_idx - 1][0], STDIN_FILENO);
                    }
                }
                
                // 设置输出
                if (redirect_count > 0) {
                    // 创建所有重定向文件
                    for (int j = 0; j < redirect_count; j++) {
                        int pos = redirect_positions[j];
                        int fd = open(tokens[pos + 1], O_CREAT | O_WRONLY | O_TRUNC, 0644);
                        if (fd < 0) {
                            print_execution_error();
                            exit(EXIT_ERROR);
                        }
                        
                        if (j == redirect_count - 1) {
                            // 最后一个重定向文件连接到标准输出
                            dup2(fd, STDOUT_FILENO);
                        }
                        close(fd);
                    }
                } else if (cmd_idx < pipe_count) {
                    dup2(pipefds[cmd_idx][1], STDOUT_FILENO);
                }
                
                // 关闭所有管道描述符
                for (int j = 0; j < pipe_count; j++) {
                    close(pipefds[j][0]);
                    close(pipefds[j][1]);
                }
                
                // 执行
                if (is_builtin) {
                    exec_builtin_cmd(current_tokens, current_token_count, 1);
                    exit(EXIT_SUCCESS);
                }
                // 在子进程中执行外部命令时修改
                else if (execvp(current_tokens[0], current_tokens) < 0) {
                    if (errno == ENOENT) {
                        // print_command_not_found();
                        exit(EXIT_CMD_NOT_FOUND);
                    } else {
                        // print_execution_error();
                        exit(EXIT_ERROR);
                    }
                }
            }
            
            // 父进程处理管道
            if (cmd_idx > 0) close(pipefds[cmd_idx - 1][0]); // 关闭前一个管道的读端
            if (cmd_idx < pipe_count) close(pipefds[cmd_idx][1]); // 关闭当前管道的写端
            
            if (head_rule != NULL) {
                trace_child(pids[cmd_idx], head_rule);
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
        
        if (WIFEXITED(status)) {
            // 根据子进程的退出状态码判断错误类型
            int exit_code = WEXITSTATUS(status);
            if (exit_code == EXIT_SANDBOX_BLOCKED) {
                continue;
            } else if (exit_code == EXIT_CMD_NOT_FOUND) {
                print_command_not_found();
            } else if (exit_code == EXIT_SYNTAX_ERROR) {
                print_invalid_syntax();
            } else if (exit_code != EXIT_SUCCESS) {
                print_execution_error();
            }
        } else if (WIFSIGNALED(status)) {
            // 被信号终止的进程视为执行错误
            print_execution_error();
        }
    }

    return 0;
}

int handle_tokens(char *tokens[], int token_count) {
    if (strcmp(tokens[0], "sandbox") == 0) {
        if (token_count < 3) {
            print_invalid_syntax();
            return 0;
        }
        
        char *filename = tokens[1];
        head_rule = NULL; // 确保规则链表为空
        head_rule = parse_rules(filename, &head_rule);
        // print_rules(head_rule);
        
        if (head_rule == NULL) {
            print_execution_error();
            return 0;
        }
        
        // 执行命令
        int result = handle_cmd(tokens + 2, token_count - 2, head_rule);
        
        // 清理规则
        free_rules(&head_rule);
        return result;
    }

    // 检查第一个命令是否为内置命令
    if (is_builtin_cmd(tokens[0])) {
        // 检查是否存在管道符号
        int has_pipe = 0;
        for (int i = 1; i < token_count; i++) {
            if (strcmp(tokens[i], "|") == 0) {
                has_pipe = 1;
                break;
            }
        }
        if (has_pipe) {
            // 有管道，使用handle_cmd处理
            return handle_cmd(tokens, token_count, NULL);
        } else {
            // 无管道，直接在主进程中执行内置命令
            return exec_builtin_cmd(tokens, token_count, 0);
        }
    }
    
    return handle_cmd(tokens, token_count, NULL);
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
        if (read == -1) return 0;
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
