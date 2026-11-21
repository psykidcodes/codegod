import { NextResponse } from 'next/server.js';
import { defaultDatabase } from '../../../lib/telemetryDatabase.js';
import { getOrCreateTenantPartition } from '../../../lib/saasEngine.js';
import {
  hashPassword,
  verifyPassword,
  detectIdentifierType,
  normalizeIdentifier,
  maskIdentifier,
  createSessionToken,
  verifySessionToken,
  generateResetCode,
  storeResetCode,
  verifyResetCode,
} from '../../../lib/auth.js';

/**
 * POST /api/auth
 * Handles tenant user Sign Up, Sign In, and Forgot Password Authenticator.
 * 
 * Query: ?action=signup | ?action=signin | ?action=signout | ?action=forgot_request | ?action=forgot_verify
 */
export async function POST(request) {
  try {
    const { searchParams } = new URL(request.url);
    const action = searchParams.get('action') || 'signin';

    if (action === 'signout') {
      return NextResponse.json({ status: 'signed_out' }, { status: 200 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ error: 'Invalid JSON payload' }, { status: 400 });
    }

    const { identifier } = body;
    if (!identifier || typeof identifier !== 'string' || !identifier.trim()) {
      return NextResponse.json({ error: 'Email or mobile number is required' }, { status: 400 });
    }

    const idType = detectIdentifierType(identifier);
    if (idType === 'invalid') {
      return NextResponse.json(
        { error: 'Identifier must be a valid email address or mobile phone number' },
        { status: 400 }
      );
    }

    const normalizedId = normalizeIdentifier(identifier, idType);

    // --- FORGOT PASSWORD STEP 1: REQUEST AUTHENTICATOR RESET CODE ---
    if (action === 'forgot_request') {
      const user = defaultDatabase.getUserByIdentifier(normalizedId);
      if (!user) {
        return NextResponse.json(
          { error: 'No tenant account found with this email or mobile number' },
          { status: 404 }
        );
      }

      const code = generateResetCode();
      storeResetCode(normalizedId, code);

      return NextResponse.json(
        {
          status: 'code_dispatched',
          maskedIdentifier: maskIdentifier(normalizedId),
          deliveryChannel: idType === 'email' ? 'Email Inbox' : 'SMS Text',
          code, // Included so the demo/authenticator UI can display simulated OTP delivery
          message: `6-digit reset code dispatched to ${maskIdentifier(normalizedId)}`,
        },
        { status: 200 }
      );
    }

    // --- FORGOT PASSWORD STEP 2: VERIFY CODE & SET NEW PASSWORD ---
    if (action === 'forgot_verify') {
      const { code, newPassword } = body;
      if (!code || typeof code !== 'string' || !code.trim()) {
        return NextResponse.json({ error: '6-digit authenticator code is required' }, { status: 400 });
      }

      if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
        return NextResponse.json(
          { error: 'New password is required and must be at least 6 characters' },
          { status: 400 }
        );
      }

      const isValidCode = verifyResetCode(normalizedId, code.trim());
      if (!isValidCode) {
        return NextResponse.json(
          { error: 'Invalid or expired 6-digit authenticator code' },
          { status: 400 }
        );
      }

      const { salt, hash } = hashPassword(newPassword);
      const updated = defaultDatabase.updateUserPassword(normalizedId, hash, salt);
      if (!updated) {
        return NextResponse.json({ error: 'Failed to update password' }, { status: 500 });
      }

      return NextResponse.json(
        {
          status: 'password_reset_success',
          message: 'Password successfully updated. You may now sign in with your new password.',
        },
        { status: 200 }
      );
    }

    // --- SIGN UP & SIGN IN REQUIRE PASSWORD ---
    const { password } = body;
    if (!password || typeof password !== 'string' || password.length < 6) {
      return NextResponse.json(
        { error: 'Password is required and must be at least 6 characters' },
        { status: 400 }
      );
    }

    // --- SIGN UP ---
    if (action === 'signup') {
      const existing = defaultDatabase.getUserByIdentifier(normalizedId);
      if (existing) {
        return NextResponse.json(
          { error: 'An account with this email or mobile number already exists' },
          { status: 409 }
        );
      }

      // Generate or normalize tenant
      const rawTenantName = body.tenantName || body.companyName || 'My Organization';
      let tenantId = body.tenantId;
      if (!tenantId || typeof tenantId !== 'string' || !tenantId.trim()) {
        tenantId = rawTenantName.toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 24);
        if (!tenantId) tenantId = `tenant-${Date.now()}`;
      } else {
        tenantId = tenantId.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
      }

      // Register tenant partition in DB & memory
      let tenant = defaultDatabase.getTenant(tenantId);
      if (!tenant) {
        tenant = defaultDatabase.registerTenant({
          tenantId,
          name: rawTenantName,
          tier: body.tier || 'pro',
          region: body.region || 'us-east-1',
          slaTarget: body.slaTarget || '99.9%',
          status: 'active',
        });
      }
      getOrCreateTenantPartition(tenantId);

      // Hash password (salt + scrypt)
      const { salt, hash } = hashPassword(password);
      const userId = `usr-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      const isHost = Boolean(body.isHost || tenantId === 'cicada-host' || normalizedId === 'host@cicada.io');
      const role = body.role || (isHost ? 'host' : 'tenant');

      defaultDatabase.createUser({
        userId,
        tenantId,
        identifier: normalizedId,
        identifierType: idType,
        passwordHash: hash,
        salt,
        isHost: isHost ? 1 : 0,
        role,
      });

      const token = createSessionToken({ userId, tenantId, identifier: normalizedId, isHost, role });

      return NextResponse.json(
        {
          status: 'authenticated',
          token,
          user: {
            userId,
            tenantId,
            maskedIdentifier: maskIdentifier(normalizedId),
            identifierType: idType,
            isHost,
            role,
          },
          tenant: {
            tenantId: tenant.tenantId,
            name: tenant.name,
            tier: tenant.tier,
            region: tenant.region,
            slaTarget: tenant.slaTarget,
          },
        },
        { status: 201 }
      );
    }

    // --- SIGN IN ---
    if (action === 'signin') {
      const user = defaultDatabase.getUserByIdentifier(normalizedId);
      if (!user) {
        return NextResponse.json(
          { error: 'Invalid email/mobile number or password' },
          { status: 401 }
        );
      }

      const isValid = verifyPassword(password, user.salt, user.passwordHash);
      if (!isValid) {
        return NextResponse.json(
          { error: 'Invalid email/mobile number or password' },
          { status: 401 }
        );
      }

      const tenant = defaultDatabase.getTenant(user.tenantId) || {
        tenantId: user.tenantId,
        name: user.tenantId,
        tier: 'enterprise',
        region: 'us-east-1',
        slaTarget: '99.99%',
      };

      const isHost = Boolean(user.isHost || user.role === 'host' || user.tenantId === 'cicada-host' || user.identifier === 'host@cicada.io');
      const role = user.role || (isHost ? 'host' : 'tenant');

      const token = createSessionToken({
        userId: user.userId,
        tenantId: user.tenantId,
        identifier: user.identifier,
        isHost,
        role,
      });

      return NextResponse.json(
        {
          status: 'authenticated',
          token,
          user: {
            userId: user.userId,
            tenantId: user.tenantId,
            maskedIdentifier: maskIdentifier(user.identifier),
            identifierType: user.identifierType,
            isHost,
            role,
          },
          tenant: {
            tenantId: tenant.tenantId,
            name: tenant.name,
            tier: tenant.tier,
            region: tenant.region,
            slaTarget: tenant.slaTarget,
          },
        },
        { status: 200 }
      );
    }

    return NextResponse.json({ error: 'Invalid action parameter' }, { status: 400 });
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Authentication failed',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}

/**
 * GET /api/auth?action=me
 * Validates session token and returns the authenticated tenant and user.
 */
export async function GET(request) {
  try {
    const authHeader = request.headers.get('authorization');
    const token = authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.substring(7).trim()
      : null;

    if (!token) {
      return NextResponse.json({ authenticated: false }, { status: 200 });
    }

    const session = verifySessionToken(token);
    if (!session) {
      return NextResponse.json({ authenticated: false }, { status: 200 });
    }

    const user = defaultDatabase.getUserById(session.userId);
    const tenant = defaultDatabase.getTenant(session.tenantId) || {
      tenantId: session.tenantId,
      name: session.tenantId,
      tier: 'enterprise',
      region: 'us-east-1',
      slaTarget: '99.99%',
    };

    const isHost = Boolean(session.isHost || user?.isHost || session.tenantId === 'cicada-host' || session.identifier === 'host@cicada.io');
    const role = session.role || user?.role || (isHost ? 'host' : 'tenant');

    return NextResponse.json(
      {
        authenticated: true,
        user: {
          userId: session.userId,
          tenantId: session.tenantId,
          maskedIdentifier: maskIdentifier(session.identifier),
          identifierType: user?.identifierType || 'email',
          isHost,
          role,
        },
        tenant: {
          tenantId: tenant.tenantId,
          name: tenant.name,
          tier: tenant.tier,
          region: tenant.region,
          slaTarget: tenant.slaTarget,
        },
      },
      { status: 200 }
    );
  } catch {
    return NextResponse.json({ authenticated: false }, { status: 200 });
  }
}
