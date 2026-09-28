#!/usr/bin/env bash
# =============================================================================
# capture_at_rest_key.sh — 通过 WorkBuddy 本地 bootstrap socket 取出 at-rest 主密钥
#
# 为什么需要：WorkBuddy 5.6.x 把登录态（含 accessToken）做了 at-rest 信封加密，
# 解密需要主密钥 symmetricKey(32 字节)。这个密钥在桌面端只通过本地 socket
# （CODEBUDDY_SIDECAR_CREDENTIAL_BOOTSTRAP_SOCKET）下发给「集成终端」子进程，
# 环境变量 WORKBUDDY_AT_REST_ENCRYPTION 只给策略串、不含密钥本身。
#
# 本脚本连该 socket 取出裸 32 字节 base64 主密钥，保存到本地密钥文件，
# 之后 refresh_token.sh 可在任意终端运行（主密钥按安装稳定，无需每次重抓）。
#
# 用法（在「WorkBuddy 桌面端集成的终端」内运行一次即可）：
#   bash capture_at_rest_key.sh
#   # 或指定路径： WB_AT_REST_KEY_FILE=/path/to/key bash capture_at_rest_key.sh
#
# 安全：密钥文件仅本机、仅自己用，已被 .gitignore 忽略，请勿提交到仓库或分享他人。
# =============================================================================
set -euo pipefail

KEY_FILE="${WB_AT_REST_KEY_FILE:-$HOME/.workbuddy/at-rest.key}"

NODE_BIN="$(command -v node || true)"
if [ -z "$NODE_BIN" ]; then
  echo "错误: 未找到 node（工作日用机器需安装 Node.js ≥ 18）" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEC="$SCRIPT_DIR/decrypt-token.js"
if [ ! -f "$DEC" ]; then
  echo "错误: 找不到 decrypt-token.js（应与本脚本同目录）" >&2
  exit 1
fi

# 通过 decrypt-token.js 的 --emit-key 连本地 socket 取主密钥
OUT="$("$NODE_BIN" "$DEC" --emit-key 2>/dev/null)"
KEY="$(printf '%s\n' "$OUT" | sed -n 's/^ATREST_KEY://p')"

if [ -z "$KEY" ]; then
  echo "错误: 未取得主密钥。" >&2
  echo "请确认本脚本是在「WorkBuddy 桌面端集成的终端」内运行（普通系统终端没有 bootstrap socket）。" >&2
  echo "若已在该终端仍失败，把 stderr 输出贴给我，我再调整 socket 收发协议。" >&2
  exit 1
fi

# 校验是 32 字节 base64
BYTES="$("$NODE_BIN" -e "console.log(Buffer.from(process.argv[1],'base64').length)" "$KEY")"
if [ "$BYTES" != "32" ]; then
  echo "错误: 取到的不是 32 字节主密钥（实际 $BYTES 字节），疑似协议变化。" >&2
  exit 1
fi

mkdir -p "$(dirname "$KEY_FILE")"
printf '%s' "$KEY" > "$KEY_FILE"
echo "已保存主密钥(裸 32 字节 base64)到: $KEY_FILE"
echo "（等同账号解密密钥，仅本机使用，已被 .gitignore 忽略，请勿提交/分享）"
echo "之后 refresh_token.sh 可在任意终端运行。"
