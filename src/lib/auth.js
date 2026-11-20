/**
 * @file auth.js
 * @description Secure Authentication & Credential Masking Module for Multi-Tenant Isolation.
 * 
 * Capabilities:
 * 1. Password Hashing & Verification:
 *    - Industry-standard scrypt derivation with random 16-byte cryptographically secure salt.
 *    - Constant-time verification using timingSafeEqual to prevent timing attacks.
 *    - Passwords remain strictly with the tenant; never stored in plaintext or logged.
 * 2. Multi-Identifier Support (Email or Mobile Number):
 *    - Automatically detects email vs E.164 / formatted mobile number.
 * 3. Secure Session Tokens:
 *    - HMAC-SHA256 signed stateless tokens containing userId, tenantId, and expiration.
 * 4. Credential & PII Masking:
 *    - Masks emails: e.g. 'admin@acme.com' -> 'a***n@acme.com'.
 *    - Masks mobile numbers: e.g. '+15551234567' -> '+1 ***-***-4567'.
 *    - Masks API tokens: e.g. 'collector-alpha-token' -> 'col-***-ken'.
 *    - Always redacts password fields to '••••••••'.
 */

import { scryptSync, randomBytes, timingSafeEqual, createHmac } from 'node:crypto';

const AUTH_SECRET = process.env.AUTH_SECRET || 'cicada-telemetry-aiops-secret-key-2026';
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Derives a secure scrypt password hash with a random salt.
 * 
 * @param {string} password 
 * @returns {{ salt: string, hash: string }}
 */
export function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 6) {
    throw new Error('Password must be at least 6 characters long');
  }
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

/**
 * Constant-time verification of password against stored salt and hash.
 * 
 * @param {string} password 
 * @param {string} salt 
 * @param {string} storedHash 
 * @returns {boolean}
 */
export function verifyPassword(password, salt, storedHash) {
  if (!password || !salt || !storedHash) return false;
  try {
    const derivedHash = scryptSync(password, salt, 64).toString('hex');
    const bufA = Buffer.from(derivedHash, 'hex');
    const bufB = Buffer.from(storedHash, 'hex');
    if (bufA.length !== bufB.length) return false;
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Detects whether an identifier is an email address or mobile phone number.
 * 
 * @param {string} identifier 
 * @returns {'email' | 'mobile' | 'invalid'}
 */
export function detectIdentifierType(identifier) {
  if (typeof identifier !== 'string') return 'invalid';
  const clean = identifier.trim();

  // Email check
  if (clean.includes('@') && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
    return 'email';
  }

  // Mobile phone number check (permits +, spaces, hyphens, parentheses, minimum 7 digits)
  const digitsOnly = clean.replace(/\D/g, '');
  if (digitsOnly.length >= 7 && digitsOnly.length <= 15) {
    return 'mobile';
  }

  return 'invalid';
}

/**
 * Formats/normalizes an identifier for consistent storage.
 * 
 * @param {string} identifier 
 * @param {'email' | 'mobile'} type 
 * @returns {string}
 */
export function normalizeIdentifier(identifier, type) {
  const clean = identifier.trim();
  if (type === 'email') {
    return clean.toLowerCase();
  }
  // Remove non-digit characters except leading '+'
  if (clean.startsWith('+')) {
    return '+' + clean.substring(1).replace(/\D/g, '');
  }
  return clean.replace(/\D/g, '');
}

/**
 * Masks an email or mobile phone number for privacy display.
 * 
 * @param {string} identifier 
 * @returns {string}
 */
export function maskIdentifier(identifier) {
  if (!identifier || typeof identifier !== 'string') return '••••';
  const clean = identifier.trim();

  // Email masking: j***e@domain.com
  if (clean.includes('@')) {
    const [user, domain] = clean.split('@');
    if (user.length <= 2) {
      return `${user[0]}***@${domain}`;
    }
    return `${user[0]}***${user[user.length - 1]}@${domain}`;
  }

  // Mobile number masking: +1 ***-***-4567 or ***-***-4567
  const digits = clean.replace(/\D/g, '');
  if (digits.length >= 7) {
    const last4 = digits.slice(-4);
    if (clean.startsWith('+')) {
      if (clean.startsWith('+1') || (digits.length === 11 && digits.startsWith('1'))) {
        return `+1 ***-***-${last4}`;
      }
      const ccLen = digits.length > 10 ? digits.length - 10 : 2;
      return `+${digits.slice(0, Math.min(ccLen, 3))} ***-***-${last4}`;
    }
    return `***-***-${last4}`;
  }

  return '••••';
}

/**
 * Masks arbitrary sensitive credentials (API tokens, passwords, keys).
 * 
 * @param {string} secret 
 * @returns {string}
 */
export function maskCredential(secret) {
  if (!secret || typeof secret !== 'string') return '••••••••';
  if (secret.length <= 6) return '••••••••';
  return `${secret.slice(0, 3)}-***-${secret.slice(-3)}`;
}

/**
 * Generates an HMAC-signed stateless session token.
 * 
 * @param {{ userId: string, tenantId: string, identifier: string }} user 
 * @param {number} [ttlMs=TOKEN_TTL_MS] 
 * @returns {string} Signed token
 */
export function createSessionToken(user, ttlMs = TOKEN_TTL_MS) {
  const payload = {
    userId: user.userId,
    tenantId: user.tenantId,
    identifier: user.identifier,
    exp: Date.now() + ttlMs,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = createHmac('sha256', AUTH_SECRET)
    .update(encodedPayload)
    .digest('base64url');
  return `${encodedPayload}.${signature}`;
}

/**
 * Verifies an HMAC-signed session token.
 * 
 * @param {string} token 
 * @returns {{ userId: string, tenantId: string, identifier: string } | null}
 */
export function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [encodedPayload, signature] = parts;
  const expectedSig = createHmac('sha256', AUTH_SECRET)
    .update(encodedPayload)
    .digest('base64url');

  const bufA = Buffer.from(signature);
  const bufB = Buffer.from(expectedSig);
  if (bufA.length !== bufB.length || !timingSafeEqual(bufA, bufB)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    if (typeof payload.exp !== 'number' || Date.now() > payload.exp) {
      return null; // Expired
    }
    return {
      userId: payload.userId,
      tenantId: payload.tenantId,
      identifier: payload.identifier,
    };
  } catch {
    return null;
  }
}

export default {
  hashPassword,
  verifyPassword,
  detectIdentifierType,
  normalizeIdentifier,
  maskIdentifier,
  maskCredential,
  createSessionToken,
  verifySessionToken,
};
