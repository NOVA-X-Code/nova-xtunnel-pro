const crypto = require('crypto');

const JA_TEST_B64 = "4paZ4paa4pab4pac4pad4pae4paf4paD4paE4paF4paG4paH4paI4paJ4paK4paQ";
const CUSTOM_ALPHABET = Buffer.from(JA_TEST_B64, 'base64').toString('utf-8');
const ALPHABET_CHARS = Array.from(CUSTOM_ALPHABET);

const DEFAULT_PASSWORD = "NovaxTunnel2026";

function generateKey(password = DEFAULT_PASSWORD) {
  const ja = Buffer.from(password, 'utf-8').toString('hex').toUpperCase();
  return crypto.createHash('sha256').update(ja, 'utf-8').digest();
}

function customHexEncode(buffer) {
  let result = '';
  for (let i = 0; i < buffer.length; i++) {
    const b = buffer[i];
    const high = (b & 0xF0) >> 4;
    const low = b & 0x0F;
    result += ALPHABET_CHARS[high] + ALPHABET_CHARS[low];
  }
  return result;
}

function customHexDecode(str) {
  const chars = Array.from(str);
  const len = Math.floor(chars.length / 2);
  const buf = Buffer.alloc(len);
  for (let i = 0; i < len; i++) {
    const high = ALPHABET_CHARS.indexOf(chars[i * 2]);
    const low = ALPHABET_CHARS.indexOf(chars[i * 2 + 1]);
    buf[i] = ((high * 16) + low) & 0xFF;
  }
  return buf.toString('utf-8');
}

function encryptConfig(message, password = DEFAULT_PASSWORD) {
  const key = generateKey(password);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const ciphertext = Buffer.concat([cipher.update(message, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const combined = Buffer.concat([iv, ciphertext, tag]);
  const b64 = combined.toString('base64');
  return customHexEncode(Buffer.from(b64, 'utf-8'));
}

function decryptConfig(obfuscatedStr, password = DEFAULT_PASSWORD) {
  const b64Str = customHexDecode(obfuscatedStr);
  const combined = Buffer.from(b64Str, 'base64');

  if (combined.length < 12 + 16) {
    throw new Error("Invalid payload length");
  }

  const iv = combined.subarray(0, 12);
  const tag = combined.subarray(combined.length - 16);
  const ciphertext = combined.subarray(12, combined.length - 16);

  const key = generateKey(password);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf-8');
}

module.exports = {
  encryptConfig,
  decryptConfig
};
