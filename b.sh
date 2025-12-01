#!/bin/bash

echo "Shell脚本 PID: $$"

# 内部函数创建子进程
create_child() {
    local level=$1
    echo "Level $level 进程 PID: $$"
    
    if [ $level -lt 3 ]; then
        # 创建下一级进程
        bash -c "$(declare -f create_child); create_child $((level+1))"
    else
        # 最终级别执行mkdir系统调用
        echo "创建目录 test_dir_$level"
        mkdir -p "test_dir_$level"
    fi
}

# 启动第一个子进程
create_child 1