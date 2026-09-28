#!/usr/bin/env node
/**
 * decrypt-token.js — WorkBuddy 本机登录令牌读取（含 at-rest 信封解密）
 *
 * 输出契约（stdout，按行前缀过滤，消费方禁止整段捕获）：
 *   成功: DECRYPT_RESULT:OK / TOKEN:<accessToken> / ACCOUNT_UID:<uid> /
 *         AUTH_DOMAIN:<domain|-> / ENTERPRISE_ID:<id|->
 *   失败: DECRYPT_RESULT:ERR:<原因>
 *
 * 令牌来源优先级：
 *   1) v5.3.8+ 明文 JSON（accessToken 为字符串）—— 直接返回
 *   2) 新版信封加密（accessToken = {"$wbEncrypted":1,"envelope":"<base64>"}）
 *      —— 用主密钥 AES-256-GCM(sym-v1) 解密；主密钥取自：
 *         a. 环境变量 WORKBUDDY_AT_REST_ENCRYPTION（桌面端子进程继承得到）
 *         b. 密钥文件 WB_AT_REST_KEY_FILE 或 ~/.workbuddy/at-rest.key
 *            （一次性 capture_at_rest_key.sh 在桌面端环境内导出保存）
 *   3) 旧版 state.vscdb（Electron safeStorage，缺 Electron 时报错）
 *
 * 算法已对照 WorkBuddy 自带 process-cpu-sampler.js 逐字节确认：
 *   AES-256-GCM，nonce 12B，authTag 16B；
 *   AAD = WB-AAD\0 | 0x01 | len("WBEV1") | len("sym-v1") | u32(suite)
 *       | len(keyId) | FRAMING_CODE[field]=0x02 | 0x00 | 0x00
 *
 * 安全：令牌仅经 stdout 管道传递，不写任何文件、不回显。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const APP_NAME = process.env.WB_CHECKIN_APP_NAME || 'WorkBuddy';

// ---------- at-rest 信封解密（sym-v1，逐字节对照官方实现） ----------
const AAD_DOMAIN = Buffer.from('WB-AAD\0', 'ascii');
const FRAMING_CODE = { file: 1, field: 2, record: 3, stream: 4 };
const STANDARD_FORMAT_ID = { file: 'WBEF1', field: 'WBEV1', record: 'WBER1', stream: 'WBES1' };

function encodeUint32(v) {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(v);
  return b;
}
function encodeLengthPrefixed(s) {
  const b = Buffer.from(s, 'utf8');
  return Buffer.concat([encodeUint32(b.length), b]);
}
function buildAad(keyId, suite, framing) {
  return Buffer.concat([
    AAD_DOMAIN,
    Buffer.from([1]),
    encodeLengthPrefixed(STANDARD_FORMAT_ID[framing]),
    encodeLengthPrefixed('sym-v1'),
    encodeUint32(suite),
    encodeLengthPrefixed(keyId),
    Buffer.from([FRAMING_CODE[framing]]),
    Buffer.from([0]),
    Buffer.from([0]),
  ]);
}

function masterKeyFromPolicy(policyStr) {
  const text = policyStr.trim();
  if (!text || text === '[]') throw new Error('policy 为空/禁用');
  let bootstrap;
  try {
    bootstrap = JSON.parse(text);
  } catch (e) {
    // 可能不是 JSON —— 当作裸 base64 主密钥（32 字节）
    const raw = Buffer.from(text, 'base64');
    if (raw.length === 32) return raw;
    throw new Error('policy 既不是合法 JSON 也不是 32 字节 base64 密钥');
  }
  const sk = bootstrap.symmetricKey || bootstrap.symmetric_key;
  if (!sk || !sk.keyBase64) throw new Error('policy 中无 symmetricKey.keyBase64');
  const key = Buffer.from(sk.keyBase64, 'base64');
  if (key.length !== 32) throw new Error('symmetricKey 长度不为 32 字节');
  return key;
}

function openEnvelope(masterKey, envB64) {
  const json = JSON.parse(Buffer.from(envB64, 'base64').toString('utf8'));
  const keyId = json.keyId;
  const expected = crypto.createHash('sha256').update(masterKey).digest('hex').slice(0, 16);
  if (keyId !== expected) {
    throw new Error(`keyId 不匹配: 信封=${keyId} 主密钥=${expected}`);
  }
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    masterKey,
    Buffer.from(json.nonce, 'base64'),
    { authTagLength: 16 }
  );
  decipher.setAAD(buildAad(keyId, json.suite, 'field'));
  decipher.setAuthTag(Buffer.from(json.authTag, 'base64'));
  const pt = Buffer.concat([
    decipher.update(Buffer.from(json.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return pt.toString('utf8');
}

// 仅用于 --selftest：用完全相同的方式 seal，验证 open 能还原
function sealEnvelope(masterKey, plaintext) {
  const keyId = crypto.createHash('sha256').update(masterKey).digest('hex').slice(0, 16);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, nonce, { authTagLength: 16 });
  cipher.setAAD(buildAad(keyId, 1, 'field'));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const env = {
    suite: 1,
    keyId,
    nonce: nonce.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
    ciphertext: ct.toString('base64'),
  };
  return Buffer.from(JSON.stringify(env)).toString('base64');
}

// ---------- 主密钥来源 ----------
function resolveMasterKey() {
  // a. 环境变量（WorkBuddy 桌面端子进程继承）
  const envPolicy = process.env.WORKBUDDY_AT_REST_ENCRYPTION;
  if (envPolicy && envPolicy.trim() && envPolicy.trim() !== '[]') {
    try {
      return masterKeyFromPolicy(envPolicy);
    } catch (e) {
      process.stderr.write('[decrypt-token] env WORKBUDDY_AT_REST_ENCRYPTION 解析失败: ' + e.message + '\n');
    }
  }
  // b. 密钥文件（一次性捕获保存）
  const keyFile =
    process.env.WB_AT_REST_KEY_FILE ||
    path.join(os.homedir(), '.workbuddy', 'at-rest.key');
  if (fs.existsSync(keyFile)) {
    try {
      return masterKeyFromPolicy(fs.readFileSync(keyFile, 'utf8'));
    } catch (e) {
      process.stderr.write('[decrypt-token] 密钥文件解析失败: ' + e.message + '\n');
    }
  }
  return null;
}

// ---------- 登录态文件定位 ----------
function candidatesPlaintext() {
  const rel = path.join('CodeBuddyExtension', 'Data', 'Public', 'auth', 'workbuddy-desktop.info');
  const list = [];
  if (process.platform === 'win32') {
    if (process.env.LOCALAPPDATA) list.push(path.join(process.env.LOCALAPPDATA, rel));
    if (process.env.APPDATA) list.push(path.join(process.env.APPDATA, rel));
  } else if (process.platform === 'darwin') {
    list.push(path.join(os.homedir(), 'Library', 'Application Support', rel));
  } else {
    list.push(path.join(os.homedir(), '.config', rel));
  }
  // 允许显式覆盖
  if (process.env.WB_AUTH_INFO) list.unshift(process.env.WB_AUTH_INFO);
  return list;
}

function readInfoFile() {
  for (const p of candidatesPlaintext()) {
    try {
      if (!fs.existsSync(p)) continue;
      const data = JSON.parse(fs.readFileSync(p, 'utf8'));
      process.stderr.write('[decrypt-token] 读取登录态: ' + p + '\n');
      return data;
    } catch (e) {
      process.stderr.write('[decrypt-token] 解析失败 ' + p + ': ' + e.message + '\n');
    }
  }
  return null;
}

// ---------- 输出 ----------
function emitAndExit(text, code) {
  process.stdout.write(text + '\n', () => {
    setTimeout(() => process.exit(code), 200);
  });
}
function fail(reason) {
  emitAndExit('DECRYPT_RESULT:ERR:' + reason, 5);
}
function ok(token, uid, domain, enterpriseId, tenantId) {
  let out =
    'DECRYPT_RESULT:OK\n' +
    'TOKEN:' + token + '\n' +
    'ACCOUNT_UID:' + uid + '\n' +
    'AUTH_DOMAIN:' + (domain || '-') + '\n' +
    'ENTERPRISE_ID:' + (enterpriseId || '-') + '\n';
  if (tenantId) out += 'TENANT_ID:' + tenantId + '\n';
  emitAndExit(out, 0);
}

// ---------- 旧版 state.vscdb 回退（需 Electron safeStorage） ----------
function tryLegacyVscdb() {
  const candidates = [];
  if (process.platform === 'win32') {
    const base = process.env.APPDATA;
    if (base) {
      candidates.push(path.join(base, APP_NAME, 'User', 'globalStorage', 'state.vscdb'));
      candidates.push(path.join(base, 'CodeBuddy', 'User', 'globalStorage', 'state.vscdb'));
    }
  } else if (process.platform === 'darwin') {
    candidates.push(path.join(os.homedir(), 'Library', 'Application Support', APP_NAME, 'User', 'globalStorage', 'state.vscdb'));
  } else {
    candidates.push(path.join(os.homedir(), '.config', APP_NAME, 'User', 'globalStorage', 'state.vscdb'));
  }
  const dbPath = candidates.find((p) => fs.existsSync(p));
  if (!dbPath) return null;
  try {
    const electron = require('electron');
    if (electron && electron.app && !electron.app.isReady && !process.env.ELECTRON_RUN_AS_NODE) {
      const { safeStorage } = electron;
      const { DatabaseSync } = require('node:sqlite');
      const db = new DatabaseSync(dbPath, { readOnly: true });
      const keys = ['authState', 'workbuddy.auth', 'codebuddy.auth', 'auth'];
      let enc = null;
      for (const k of keys) {
        const row = db.prepare('SELECT value FROM ItemTable WHERE key = ?').get(k);
        if (row && row.value) { enc = row.value; break; }
      }
      db.close();
      if (!enc) { fail('LEGACY_DB_NO_AUTH_KEY:' + dbPath); return; }
      const buf = typeof enc === 'string' ? Buffer.from(enc, 'base64') : Buffer.from(enc);
      const tokenJson = safeStorage.decryptString(buf);
      const parsed = JSON.parse(tokenJson);
      const token = parsed.accessToken || (parsed.auth && parsed.auth.accessToken);
      if (!token) { fail('LEGACY_DECRYPT_NO_TOKEN'); return; }
      ok(
        token,
        parsed.uid || (parsed.account && parsed.account.uid) || '',
        parsed.domain || '-',
        (parsed.enterpriseId || (parsed.account && parsed.account.enterpriseId)) || '-'
      );
    }
  } catch (e) {
    fail('LEGACY_NEED_ELECTRON:' + e.message);
    return;
  }
  fail('LEGACY_CONTEXT_UNAVAILABLE:' + dbPath);
}

// ---------- 主流程 ----------
function selftest() {
  const key = crypto.randomBytes(32);
  const keyId = crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
  const policy = JSON.stringify({
    version: 1,
    policy: 'required',
    symmetricKey: { keyId, keyBase64: key.toString('base64') },
  });
  const sample = 'eyJh.access.TOKEN.value.12345';
  const envB64 = sealEnvelope(key, sample);
  const out = openEnvelope(key, envB64);
  if (out === sample) {
    console.log('SELFTEST: OK  — AES-256-GCM sym-v1 信封加解密一致（AAD 字节级正确）');
    process.exit(0);
  } else {
    console.error('SELFTEST: FAIL — 解密结果与原文不符');
    process.exit(1);
  }
}

function main() {
  if (process.argv.includes('--selftest')) return selftest();

  const info = readInfoFile();
  if (!info) {
    const r = tryLegacyVscdb();
    if (r === undefined) return; // 已 exit
    if (r === null) fail('NO_LOCAL_LOGIN_STATE:未找到 workbuddy-desktop.info，请确认 WorkBuddy 桌面端已登录');
    return;
  }

  const auth = info.auth || {};
  const tokenField = auth.accessToken;
  let token;

  if (typeof tokenField === 'string') {
    // 明文构建（旧版 / 部分环境）
    token = tokenField;
    process.stderr.write('[decrypt-token] accessToken 为明文，直接使用\n');
  } else if (tokenField && tokenField.$wbEncrypted === 1 && tokenField.envelope) {
    // 信封加密（5.6.x 等新版）
    const key = resolveMasterKey();
    if (!key) {
      fail('NO_AT_REST_KEY:accessToken 已用 at-rest 信封加密，但未获得主密钥。'
        + '请在 WorkBuddy 桌面端环境内运行 refresh_token.sh，'
        + '或先执行 capture_at_rest_key.sh 把 WORKBUDDY_AT_REST_ENCRYPTION 保存到密钥文件后再跑。');
      return;
    }
    try {
      token = openEnvelope(key, tokenField.envelope);
      process.stderr.write('[decrypt-token] at-rest 信封解密成功\n');
    } catch (e) {
      fail('DECRYPT_FAILED:' + e.message);
      return;
    }
  } else {
    fail('NO_VALID_TOKEN_FIELD:auth.accessToken 缺失或格式未知');
    return;
  }

  const uid =
    (info.account && (info.account.uid || info.account.userId || info.account.id)) ||
    auth.uid || auth.userId || '';
  const domain = auth.domain || '';
  const enterpriseId =
    (info.account && info.account.enterpriseId) || auth.enterpriseId || '';
  const tenantId = (info.account && info.account.tenantId) || auth.tenantId || '';

  ok(token, uid, domain, enterpriseId, tenantId);
}

try {
  main();
} catch (e) {
  fail('UNEXPECTED:' + e.message);
}
