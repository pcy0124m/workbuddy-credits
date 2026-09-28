#!/usr/bin/env bash
# =============================================================================
# capture_at_rest_key.sh — 一次性把 WorkBuddy 的 at-rest 主密钥策略导出到密钥文件
#
# 为什么需要：WorkBuddy 5.6.x 把登录态（含 accessToken）做了 at-rest 信封加密，
# 解密需要主密钥，而主密钥只在 WorkBuddy 桌面端派生的进程环境里以环境变量
# WORKBUDDY_AT_REST_ENCRYPTION 提供。本脚本把该值保存到本地密钥文件，
# 之后 refresh_token.sh 可在任意终端运行（主密钥按安装稳定，无需每次重抓）。
#
# 用法（在「WorkBuddy 桌面端派生的终端」内运行一次即可）：
#   bash capture_at_rest_key.sh
#   # 或指定路径： WB_AT_REST_KEY_FILE=/path/to/key bash capture_at_rest_key.sh
#
# 安全：密钥文件仅本机、仅自己用，请勿提交到仓库或分享给他人。
# =============================================================================
set -euo pipefail

KEY_FILE="${WB_AT_REST_KEY_FILE:-$HOME/.workbuddy/at-rest.key}"
POLICY="${WORKBUDDY_AT_REST_ENCRYPTION:-}"

if [ -z "$POLICY" ] || [ "$POLICY" = "[]" ]; then
  echo "错误: 当前环境没有 WORKBUDDY_AT_REST_ENCRYPTION。" >&2
  echo "请确认本脚本是在「WorkBuddy 桌面端派生的终端」内运行（普通系统终端没有该变量）。" >&2
  echo "若普通终端也没有该变量，请联系我，我再加「连接桌面端守护进程 bootstrap 套接字」的自动获取方式。" >&2
  exit 1
fi

mkdir -p "$(dirname "$KEY_FILE")"
printf '%s' "$POLICY" > "$KEY_FILE"
echo "已保存 at-rest 主密钥策略到: $KEY_FILE"
echo "（该值等同账号密钥，仅本机使用，请勿提交/分享。之后 refresh_token.sh 任意终端可跑）"
