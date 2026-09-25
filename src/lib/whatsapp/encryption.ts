import crypto from 'crypto';

/**
 * WhatsApp token encryption.
 *
 * Current format — GCM:
 *   <iv-hex>:<ciphertext-hex>:<authTag-hex>
 *
 * Legacy format — CBC:
 *   <iv-hex>:<ciphertext-hex>
 *
 * ENCRYPTION_KEY must be:
 *   - exactly 64 hexadecimal characters
 *   - 32 bytes when decoded
 *   - suitable for AES-256
 */

// Read encryption key from environment
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Validate that the environment variable exists
if (!ENCRYPTION_KEY) {
  throw new Error(
    'ENCRYPTION_KEY is not configured. Add it to your Vercel Environment Variables.'
  );
}

// Validate that the key is exactly 64 hexadecimal characters
if (!/^[0-9a-fA-F]{64}$/.test(ENCRYPTION_KEY)) {
  throw new Error(
    `ENCRYPTION_KEY must be exactly 64 hexadecimal characters. Received length: ${ENCRYPTION_KEY.length}`
  );
}

// Convert 64 hex characters → 32 bytes
const KEY = Buffer.from(ENCRYPTION_KEY, 'hex');

// Extra safety check
if (KEY.length !== 32) {
  throw new Error(
    `ENCRYPTION_KEY must decode to exactly 32 bytes. Received ${KEY.length} bytes.`
  );
}

// GCM uses a 12-byte IV
const GCM_IV_LENGTH = 12;

// Legacy CBC uses a 16-byte IV
const CBC_IV_LENGTH = 16;

// GCM authentication tag is 16 bytes
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypt text using AES-256-GCM.
 *
 * Output format:
 *
 * <iv-hex>:<ciphertext-hex>:<authTag-hex>
 */
export function encrypt(text: string): string {
  const iv = crypto.randomBytes(GCM_IV_LENGTH);

  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');

  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
}

/**
 * Decrypt an encrypted WhatsApp token.
 *
 * Supports:
 *
 * GCM:
 *   <iv>:<ciphertext>:<authTag>
 *
 * Legacy CBC:
 *   <iv>:<ciphertext>
 */
export function decrypt(encryptedText: string): string {
  const parts = encryptedText.split(':');

  /**
   * --------------------------------------------------
   * GCM — current format
   * --------------------------------------------------
   */
  if (parts.length === 3) {
    const [ivHex, ctHex, tagHex] = parts;

    const iv = Buffer.from(ivHex, 'hex');

    if (iv.length !== GCM_IV_LENGTH) {
      throw new Error(
        `Encrypted token has unexpected GCM IV length ${iv.length}`
      );
    }

    const authTag = Buffer.from(tagHex, 'hex');

    if (authTag.length !== AUTH_TAG_LENGTH) {
      throw new Error(
        `Encrypted token has unexpected auth-tag length ${authTag.length}`
      );
    }

    const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ctHex, 'hex', 'utf8');

    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * --------------------------------------------------
   * CBC — legacy format
   * --------------------------------------------------
   */
  if (parts.length === 2) {
    const [ivHex, ctHex] = parts;

    const iv = Buffer.from(ivHex, 'hex');

    if (iv.length !== CBC_IV_LENGTH) {
      throw new Error(
        `Encrypted token has unexpected CBC IV length ${iv.length}`
      );
    }

    const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, iv);

    let decrypted = decipher.update(ctHex, 'hex', 'utf8');

    decrypted += decipher.final('utf8');

    return decrypted;
  }

  throw new Error(
    `Encrypted token has unrecognised format (expected 1 or 2 colons, got ${
      parts.length - 1
    })`
  );
}

/**
 * Check whether an encrypted token is using
 * the legacy CBC format.
 *
 * CBC:
 *   iv:ciphertext
 *
 * GCM:
 *   iv:ciphertext:authTag
 */
export function isLegacyFormat(encryptedText: string): boolean {
  return encryptedText.split(':').length === 2;
}
