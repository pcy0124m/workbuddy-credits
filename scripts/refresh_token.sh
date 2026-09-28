#!/usr/bin/env bash
# =============================================================================
# refresh_token.sh — 把本机 WorkBuddy 登录态导出为 token，注入 GitHub repo secret
#
# 用法:
#   bash refresh_token.sh <owner/repo>
#   bash refresh_token.sh myname/workbuddy-credits
#
# 设计（对应需求「云端没有本机登录态，token 不能读本地拿」）：
#   本机（你常开的那台、装了 WorkBuddy 桌面端并登录过）运行此脚本：
#     1) 用 decrypt-token.js 读本机登录态，解出 accessToken / uid / domain / entId
#     2) 用 gh CLI 把这些值写入仓库 secret（明文只进 secret 存储，不回显/不落盘/不进仓库）
#   GitHub Actions 云端运行时只从 secret 读，绝不再读本机登录态。
#
# 安全：
#   - token 明文不 echo、不写文件、不进 git 仓库、不进日志
#   - 仅在 stdout 解析用，stderr 只放脚本自身提示
#   - 重新运行即可刷新（token 变更/过期后重跑一次本脚本）
# =============================================================================
set -euo pipefail

REPO="${1:?用法: bash refresh_token.sh <owner/repo>}"

# 解释器路径动态取，不写死版本号
NODE_BIN="$(command -v node || true)"
if [ -z "$NODE_BIN" ]; then
  echo "错误: 未找到 node（工作日用机器需安装 Node.js ≥ 18）" >&2
  exit 1
fi
GH_BIN="$(command -v gh || true)"
if [ -z "$GH_BIN" ]; then
  echo "错误: 未找到 gh CLI（https://cli.github.com），请先安装并 gh auth login" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEC="$SCRIPT_DIR/decrypt-token.js"
if [ ! -f "$DEC" ]; then
  echo "错误: 找不到 decrypt-token.js（应与本脚本同目录）" >&2
  exit 1
fi

# 仅在 stderr 暴露脚本日志；stdout 交给后续解析
OUT="$("$NODE_BIN" "$DEC" 2>/dev/null)"
RESULT_LINE="$(printf '%s\n' "$OUT" | grep '^DECRYPT_RESULT:' || true)"
if [ "$RESULT_LINE" != "DECRYPT_RESULT:OK" ]; then
  echo "错误: 读取本机登录态失败 -> ${RESULT_LINE:-无输出}。请确认 WorkBuddy 桌面端已登录并打开过一次。" >&2
  exit 1
fi

TOKEN="$(printf '%s\n' "$OUT"   | sed -n 's/^TOKEN://p')"
UID_="$(printf '%s\n' "$OUT"    | sed -n 's/^ACCOUNT_UID://p')"
DOMAIN="$(printf '%s\n' "$OUT"  | sed -n 's/^AUTH_DOMAIN://p')"
ENTID="$(printf '%s\n' "$OUT"   | sed -n 's/^ENTERPRISE_ID://p')"

# 注入 secret（gh 不会在终端回显 secret 值；值只存进 GitHub Encrypted Secrets）
"$GH_BIN" secret set WORKBUDDY_TOKEN  --body "$TOKEN"  --repo "$REPO"
"$GH_BIN" secret set WORKBUDDY_UID    --body "$UID_"   --repo "$REPO"
"$GH_BIN" secret set WORKBUDDY_DOMAIN --body "$DOMAIN" --repo "$REPO"
"$GH_BIN" secret set WORKBUDDY_ENTID  --body "$ENTID"  --repo "$REPO"

echo "已注入 secret 到 $REPO："
echo "  WORKBUDDY_TOKEN / WORKBUDDY_UID / WORKBUDDY_DOMAIN / WORKBUDDY_ENTID"
echo "（token 明文未打印、未落盘、未进仓库；需要更新时重新运行本脚本即可）"
