import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  hashPassword,
  verifyPassword,
  detectIdentifierType,
  normalizeIdentifier,
  maskIdentifier,
  maskCredential,
  createSessionToken,
  verifySessionToken,
} from '../src/lib/auth.js';
import { defaultDatabase } from '../src/lib/telemetryDatabase.js';
import { POST as authPost, GET as authGet } from '../src/app/api/auth/route.js';

test('1. Password Hashing & Verification: scrypt with random salt and constant-time check', () => {
  const password = 'SuperSecretTenantPassword123!';
  const { salt, hash } = hashPassword(password);

  assert.ok(salt && salt.length === 32, 'Salt should be a 32-character hex string (16 bytes)');
  assert.ok(hash && hash.length === 128, 'Hash should be a 128-character hex string (64 bytes)');

  // Verify correct password succeeds
  const isValid = verifyPassword(password, salt, hash);
  assert.strictEqual(isValid, true, 'Valid password should verify successfully');

  // Verify wrong password fails
  const isInvalid = verifyPassword('WrongPassword123!', salt, hash);
  assert.strictEqual(isInvalid, false, 'Incorrect password should fail verification');

  // Verify different salt yields different hash
  const { salt: salt2, hash: hash2 } = hashPassword(password);
  assert.notStrictEqual(salt, salt2, 'Salts must be randomly generated and unique per hash');
  assert.notStrictEqual(hash, hash2, 'Hashes must differ across different salts');

  // Rejects passwords shorter than 6 characters
  assert.throws(() => hashPassword('12345'), /at least 6 characters/);
});

test('2. Identifier Detection & Normalization: supports Email and Mobile Numbers', () => {
  // Emails
  assert.strictEqual(detectIdentifierType('operator@acme.corp'), 'email');
  assert.strictEqual(detectIdentifierType('SEC.OPS@shield.io'), 'email');
  assert.strictEqual(normalizeIdentifier('  Operator@Acme.Corp  ', 'email'), 'operator@acme.corp');

  // Mobile Numbers (various international and local formats)
  assert.strictEqual(detectIdentifierType('+1 (555) 123-4567'), 'mobile');
  assert.strictEqual(detectIdentifierType('+44 7911 123456'), 'mobile');
  assert.strictEqual(detectIdentifierType('9876543210'), 'mobile');
  assert.strictEqual(normalizeIdentifier('+1 (555) 123-4567', 'mobile'), '+15551234567');

  // Invalid Identifiers
  assert.strictEqual(detectIdentifierType('not-an-email-or-phone'), 'invalid');
  assert.strictEqual(detectIdentifierType('123'), 'invalid');
});

test('3. Credential & PII Masking: emails, mobile numbers, and secret tokens', () => {
  // Email masking
  const maskedEmail = maskIdentifier('admin@acme.com');
  assert.strictEqual(maskedEmail, 'a***n@acme.com');
  assert.strictEqual(maskIdentifier('operator@defense.gov'), 'o***r@defense.gov');

  // Mobile number masking
  const maskedMobile = maskIdentifier('+15551234567');
  assert.strictEqual(maskedMobile, '+1 ***-***-4567');
  assert.strictEqual(maskIdentifier('9876543210'), '***-***-3210');

  // Secret / API token masking
  const maskedToken = maskCredential('collector-alpha-token');
  assert.strictEqual(maskedToken, 'col-***-ken');
  assert.strictEqual(maskCredential('sk-proj-998877665544332211'), 'sk--***-211');
  assert.strictEqual(maskCredential(null), '••••••••');
});

test('4. Session Token: HMAC-SHA256 stateless tokens with tamper protection', () => {
  const user = { userId: 'usr-test-101', tenantId: 'cyber-vault', identifier: 'admin@cybervault.io' };
  const token = createSessionToken(user);

  assert.ok(token && token.includes('.'), 'Token must contain payload and signature segments');

  const verified = verifySessionToken(token);
  assert.ok(verified, 'Valid token must verify successfully');
  assert.strictEqual(verified.userId, 'usr-test-101');
  assert.strictEqual(verified.tenantId, 'cyber-vault');
  assert.strictEqual(verified.identifier, 'admin@cybervault.io');

  // Tampered token check
  const [b64Payload] = token.split('.');
  const forgedToken = `${b64Payload}.tampered_signature_bits`;
  const invalidSession = verifySessionToken(forgedToken);
  assert.strictEqual(invalidSession, null, 'Tampered token signature must be rejected');
});

test('5. Auth Route Integration: Sign Up creates tenant partition and user with masked credentials', async () => {
  const uniqueId = `tenant-${Date.now()}`;
  const signupReq = new Request('http://localhost:3000/api/auth?action=signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier: `director@${uniqueId}.com`,
      password: 'SecureEnterprisePassword2026!',
      tenantId: uniqueId,
      tenantName: 'Zero Trust Operations',
      tier: 'enterprise',
    }),
  });

  const res = await authPost(signupReq);
  assert.strictEqual(res.status, 201);
  const data = await res.json();

  assert.strictEqual(data.status, 'authenticated');
  assert.ok(data.token, 'Should return session token');
  assert.strictEqual(data.user.tenantId, uniqueId);
  assert.strictEqual(data.user.maskedIdentifier, `d***r@${uniqueId}.com`);
  assert.strictEqual(data.tenant.tenantId, uniqueId);

  // Check database persistence: password must NEVER be in plaintext
  const storedUser = defaultDatabase.getUserByIdentifier(`director@${uniqueId}.com`);
  assert.ok(storedUser, 'User must exist in SQLite database');
  assert.notStrictEqual(storedUser.passwordHash, 'SecureEnterprisePassword2026!', 'Plaintext password must never be stored');
  assert.ok(storedUser.salt, 'Salt must be stored');
});

test('6. Auth Route Integration: Sign In validates scrypt hash and constant-time check', async () => {
  // Use seeded default admin user
  const signinReq = new Request('http://localhost:3000/api/auth?action=signin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier: 'admin@acme.com',
      password: 'Password123!',
    }),
  });

  const res = await authPost(signinReq);
  assert.strictEqual(res.status, 200);
  const data = await res.json();

  assert.strictEqual(data.status, 'authenticated');
  assert.strictEqual(data.user.tenantId, 'acme-corp');
  assert.strictEqual(data.user.maskedIdentifier, 'a***n@acme.com');

  // Verify GET /api/auth?action=me using returned token
  const meReq = new Request('http://localhost:3000/api/auth?action=me', {
    method: 'GET',
    headers: { Authorization: `Bearer ${data.token}` },
  });
  const meRes = await authGet(meReq);
  assert.strictEqual(meRes.status, 200);
  const meData = await meRes.json();
  assert.strictEqual(meData.authenticated, true);
  assert.strictEqual(meData.user.tenantId, 'acme-corp');
  assert.strictEqual(meData.user.maskedIdentifier, 'a***n@acme.com');

  // Sign in with invalid password returns 401
  const badSigninReq = new Request('http://localhost:3000/api/auth?action=signin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier: 'admin@acme.com',
      password: 'IncorrectPassword!',
    }),
  });
  const badRes = await authPost(badSigninReq);
  assert.strictEqual(badRes.status, 401);
});

test('7. Auth Route Integration: Mobile Number Sign Up & Sign In with password isolation', async () => {
  const mobile = '+1 555-987-6543';
  const password = 'MobileSecurePass2026!';
  const tenantId = `mobile-vault-${Date.now()}`;

  // Sign up with mobile number
  const signupReq = new Request('http://localhost:3000/api/auth?action=signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier: mobile,
      password,
      tenantId,
      tenantName: 'Mobile Operations Corp',
    }),
  });

  const signupRes = await authPost(signupReq);
  assert.strictEqual(signupRes.status, 201);
  const signupData = await signupRes.json();
  assert.strictEqual(signupData.status, 'authenticated');
  assert.strictEqual(signupData.user.maskedIdentifier, '+1 ***-***-6543');
  assert.strictEqual(signupData.user.identifierType, 'mobile');

  // Sign in with mobile number (even formatted differently)
  const signinReq = new Request('http://localhost:3000/api/auth?action=signin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier: '+15559876543',
      password,
    }),
  });

  const signinRes = await authPost(signinReq);
  assert.strictEqual(signinRes.status, 200);
  const signinData = await signinRes.json();
  assert.strictEqual(signinData.user.tenantId, tenantId);
  assert.strictEqual(signinData.user.maskedIdentifier, '+1 ***-***-6543');
});

test('8. Auth Route Integration: Forgot Password Authenticator OTP flow and password reset', async () => {
  const identifier = 'reset-test@acme.com';
  const initialPassword = 'InitialPass123!';
  const newPassword = 'BrandNewSecurePass999!';
  const tenantId = `tenant-reset-${Date.now()}`;

  // 1. Create user account
  const signupReq = new Request('http://localhost:3000/api/auth?action=signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier,
      password: initialPassword,
      tenantId,
      tenantName: 'Reset Testing Ltd',
    }),
  });
  await authPost(signupReq);

  // 2. Request Forgot Password Authenticator Code
  const forgotReq = new Request('http://localhost:3000/api/auth?action=forgot_request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier }),
  });
  const forgotRes = await authPost(forgotReq);
  assert.strictEqual(forgotRes.status, 200);
  const forgotData = await forgotRes.json();
  assert.strictEqual(forgotData.status, 'code_dispatched');
  assert.ok(forgotData.code && forgotData.code.length === 6, 'Should dispatch 6-digit code');

  // 3. Attempt reset with wrong code
  const badVerifyReq = new Request('http://localhost:3000/api/auth?action=forgot_verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier,
      code: '000000',
      newPassword,
    }),
  });
  const badVerifyRes = await authPost(badVerifyReq);
  assert.strictEqual(badVerifyRes.status, 400);

  // 4. Reset with valid code
  const goodVerifyReq = new Request('http://localhost:3000/api/auth?action=forgot_verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier,
      code: forgotData.code,
      newPassword,
    }),
  });
  const goodVerifyRes = await authPost(goodVerifyReq);
  assert.strictEqual(goodVerifyRes.status, 200);
  const goodVerifyData = await goodVerifyRes.json();
  assert.strictEqual(goodVerifyData.status, 'password_reset_success');

  // 5. Sign in with old password fails
  const oldSigninReq = new Request('http://localhost:3000/api/auth?action=signin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier,
      password: initialPassword,
    }),
  });
  const oldSigninRes = await authPost(oldSigninReq);
  assert.strictEqual(oldSigninRes.status, 401);

  // 6. Sign in with new password succeeds
  const newSigninReq = new Request('http://localhost:3000/api/auth?action=signin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identifier,
      password: newPassword,
    }),
  });
  const newSigninRes = await authPost(newSigninReq);
  assert.strictEqual(newSigninRes.status, 200);
  const newSigninData = await newSigninRes.json();
  assert.strictEqual(newSigninData.status, 'authenticated');
  assert.strictEqual(newSigninData.user.tenantId, tenantId);
});


