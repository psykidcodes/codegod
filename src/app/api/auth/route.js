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
} from '../../../lib/auth.js';

/**
 * POST /api/auth
 * Handles tenant user Sign Up and Sign In with Email or Mobile Number.
 * 
 * Query: ?action=signup | ?action=signin | ?action=signout
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

    const { identifier, password } = body;
    if (!identifier || typeof identifier !== 'string' || !identifier.trim()) {
      return NextResponse.json({ error: 'Email or mobile number is required' }, { status: 400 });
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
      return NextResponse.json(
        { error: 'Password is required and must be at least 6 characters' },
        { status: 400 }
      );
    }

    const idType = detectIdentifierType(identifier);
    if (idType === 'invalid') {
      return NextResponse.json(
        { error: 'Identifier must be a valid email address or mobile phone number' },
        { status: 400 }
      );
    }

    const normalizedId = normalizeIdentifier(identifier, idType);

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

      defaultDatabase.createUser({
        userId,
        tenantId,
        identifier: normalizedId,
        identifierType: idType,
        passwordHash: hash,
        salt,
      });

      const token = createSessionToken({ userId, tenantId, identifier: normalizedId });

      return NextResponse.json(
        {
          status: 'authenticated',
          token,
          user: {
            userId,
            tenantId,
            maskedIdentifier: maskIdentifier(normalizedId),
            identifierType: idType,
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

      const token = createSessionToken({
        userId: user.userId,
        tenantId: user.tenantId,
        identifier: user.identifier,
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

    return NextResponse.json(
      {
        authenticated: true,
        user: {
          userId: session.userId,
          tenantId: session.tenantId,
          maskedIdentifier: maskIdentifier(session.identifier),
          identifierType: user?.identifierType || 'email',
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
