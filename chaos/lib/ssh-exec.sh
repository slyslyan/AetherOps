#!/bin/bash
# ssh-exec.sh — SSH 执行封装
# 用法: source chaos/lib/ssh-exec.sh

# 在服务器上执行命令（输出到 stdout）
exec_ssh() {
    ssh "${CHAOS_SSH_USER}@${CHAOS_SSH_HOST}" "$@"
}

# 在服务器上以 sudo 执行命令
exec_sudo() {
    ssh "${CHAOS_SSH_USER}@${CHAOS_SSH_HOST}" "sudo $*"
}

# 测试 SSH 连通性
test_ssh() {
    if exec_ssh "echo ok" 2>/dev/null | grep -q ok; then
        return 0
    fi
    return 1
}

# 上传文件到服务器
scp_upload() {
    local local_file="$1"
    local remote_path="${2:-/tmp/}"
    scp "$local_file" "${CHAOS_SSH_USER}@${CHAOS_SSH_HOST}:${remote_path}"
}

# 从服务器下载文件
scp_download() {
    local remote_file="$1"
    local local_path="${2:-./}"
    scp "${CHAOS_SSH_USER}@${CHAOS_SSH_HOST}:${remote_file}" "$local_path"
}
