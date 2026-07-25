/**
 * tests/sep0010.test.js
 *
 * Unit tests for the SEP-0010 Web Authentication implementation in
 * frontend/lumenflow-shared.js.
 *
 * Run with:
 *   node --test tests/sep0010.test.js          (Node ≥ 18 built-in runner)
 *   npx jest tests/sep0010.test.js             (if Jest is configured)
 */

'use strict';

const assert = require('assert');
const { describe, it, before, beforeEach, afterEach } = require('node:test');

// ── Load module under test ────────────────────────────────────────────────────
// lumenflow-shared.js guards browser globals; load it in Node safely.

// Stub sessionStorage so the module can initialise without a browser.
const _store = {};
const sessionStorageStub = {
  getItem:    (k)    => Object.prototype.hasOwnProperty.call(_store, k) ? _store[k] : null,
  setItem:    (k, v) => { _store[k] = v; },
  removeItem: (k)    => { delete _store[k]; },
  clear:      ()     => { Object.keys(_store).forEach(k => delete _store[k]); },
};

// Expose stubs before requiring the module
global.sessionStorage = sessionStorageStub;
global.window = { sessionStorage: sessionStorageStub };  // minimal window

const {
  authenticate,
  getStoredToken,
  clearToken,
  storeToken,
  fetchChallenge,
  verifyChallenge,
  getAuthToken,
  SUPPORTED_WALLETS,
  JWT_STORAGE_KEY,
  JWT_TTL_MS,
  _buildDemoToken,
  _b64url,
} = require('../frontend/lumenflow-shared.js');

// ── Helpers ───────────────────────────────────────────────────────────────────

const ACCOUNT_A = 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN';
const ACCOUNT_B = 'GBXGQJWVLWOYHFLVTKWV5FGHA3LNYY2JQKM7OAJAUEQFU6LPCSEFVXON';

/** Clear the stub sessionStorage before each test. */
function resetStorage() {
  sessionStorageStub.clear();
}

/** Build a minimal fetch mock that returns a canned response. */
function makeFetchMock(responses) {
  let callIndex = 0;
  return async (url, opts) => {
    const entry = responses[callIndex++] || responses[responses.length - 1];
    return {
      ok:     entry.ok !== false,
      status: entry.status || 200,
      statusText: entry.statusText || 'OK',
      json:   async () => entry.body,
      text:   async () => (typeof entry.body === 'string' ? entry.body : JSON.stringify(entry.body)),
      _url:   url,
      _opts:  opts,
    };
  };
}

// ── SUPPORTED_WALLETS ─────────────────────────────────────────────────────────

describe('SUPPORTED_WALLETS', () => {
  it('contains expected wallet identifiers', () => {
    assert.strictEqual(SUPPORTED_WALLETS.FREIGHTER, 'freighter');
    assert.strictEqual(SUPPORTED_WALLETS.LOBSTR,    'lobstr');
    assert.strictEqual(SUPPORTED_WALLETS.SOLAR,     'solar');
  });

  it('is frozen (immutable)', () => {
    assert.ok(Object.isFrozen(SUPPORTED_WALLETS));
  });
});

// ── JWT_STORAGE_KEY ───────────────────────────────────────────────────────────

describe('JWT_STORAGE_KEY', () => {
  it('generates correct key for a given account', () => {
    assert.strictEqual(JWT_STORAGE_KEY(ACCOUNT_A), `lumenflow_jwt_${ACCOUNT_A}`);
  });

  it('generates distinct keys for different accounts', () => {
    assert.notStrictEqual(JWT_STORAGE_KEY(ACCOUNT_A), JWT_STORAGE_KEY(ACCOUNT_B));
  });
});

// ── Token cache: storeToken / getStoredToken / clearToken ─────────────────────

describe('Token caching', () => {
  beforeEach(() => resetStorage());

  it('stores and retrieves a token', () => {
    storeToken(ACCOUNT_A, 'my.jwt.token');
    assert.strictEqual(getStoredToken(ACCOUNT_A), 'my.jwt.token');
  });

  it('returns null for an account with no stored token', () => {
    assert.strictEqual(getStoredToken(ACCOUNT_A), null);
  });

  it('returns null and removes the key when the token has expired', () => {
    // Write an already-expired entry directly into the store
    const key = JWT_STORAGE_KEY(ACCOUNT_A);
    _store[key] = JSON.stringify({
      token:     'expired.token',
      expiresAt: Date.now() - 1000, // 1 second in the past
    });
    assert.strictEqual(getStoredToken(ACCOUNT_A), null);
    // Key should have been cleaned up
    assert.strictEqual(_store[key], undefined);
  });

  it('returns the token when it has not yet expired', () => {
    const key = JWT_STORAGE_KEY(ACCOUNT_A);
    _store[key] = JSON.stringify({
      token:     'valid.token',
      expiresAt: Date.now() + 60_000, // 1 minute in the future
    });
    assert.strictEqual(getStoredToken(ACCOUNT_A), 'valid.token');
  });

  it('clears the token for a given account', () => {
    storeToken(ACCOUNT_A, 'some.token');
    clearToken(ACCOUNT_A);
    assert.strictEqual(getStoredToken(ACCOUNT_A), null);
  });

  it('clearToken does not affect other accounts', () => {
    storeToken(ACCOUNT_A, 'token-a');
    storeToken(ACCOUNT_B, 'token-b');
    clearToken(ACCOUNT_A);
    assert.strictEqual(getStoredToken(ACCOUNT_A), null);
    assert.strictEqual(getStoredToken(ACCOUNT_B), 'token-b');
  });

  it('handles corrupt JSON in sessionStorage gracefully', () => {
    _store[JWT_STORAGE_KEY(ACCOUNT_A)] = 'not-valid-json{{';
    assert.strictEqual(getStoredToken(ACCOUNT_A), null);
  });

  it('stores tokens with a 24-hour TTL', () => {
    const before = Date.now();
    storeToken(ACCOUNT_A, 'ttl.test.token');
    const raw = JSON.parse(_store[JWT_STORAGE_KEY(ACCOUNT_A)]);
    const after = Date.now();
    assert.ok(raw.expiresAt >= before + JWT_TTL_MS);
    assert.ok(raw.expiresAt <= after + JWT_TTL_MS);
  });
});

// ── Challenge construction: fetchChallenge ────────────────────────────────────

describe('fetchChallenge', () => {
  let originalFetch;
  before(() => { originalFetch = global.fetch; });
  afterEach(() => { global.fetch = originalFetch; });

  it('calls the auth endpoint with ?account= query param', async () => {
    let capturedUrl;
    global.fetch = async (url, _opts) => {
      capturedUrl = url;
      return {
        ok:   true,
        json: async () => ({
          transaction:        'AAAA==',
          network_passphrase: 'Test SDF Network ; September 2015',
        }),
        text: async () => '',
      };
    };

    await fetchChallenge('https://auth.example.com/auth', ACCOUNT_A);
    assert.ok(capturedUrl.includes(`account=${ACCOUNT_A}`));
    assert.ok(capturedUrl.startsWith('https://auth.example.com/auth'));
  });

  it('returns transaction XDR and network_passphrase', async () => {
    global.fetch = makeFetchMock([{
      body: {
        transaction:        'CHALLENGE_XDR',
        network_passphrase: 'Test SDF Network ; September 2015',
      },
    }]);

    const result = await fetchChallenge('https://auth.example.com/auth', ACCOUNT_A);
    assert.strictEqual(result.transaction, 'CHALLENGE_XDR');
    assert.strictEqual(result.network_passphrase, 'Test SDF Network ; September 2015');
  });

  it('throws on non-200 response', async () => {
    global.fetch = makeFetchMock([{ ok: false, status: 401, body: 'Unauthorized' }]);

    await assert.rejects(
      () => fetchChallenge('https://auth.example.com/auth', ACCOUNT_A),
      (err) => {
        assert.ok(err.message.includes('401'));
        return true;
      },
    );
  });

  it('throws when transaction field is missing', async () => {
    global.fetch = makeFetchMock([{
      body: { network_passphrase: 'Test SDF Network ; September 2015' },
    }]);

    await assert.rejects(
      () => fetchChallenge('https://auth.example.com/auth', ACCOUNT_A),
      /missing "transaction"/,
    );
  });

  it('throws when network_passphrase field is missing', async () => {
    global.fetch = makeFetchMock([{
      body: { transaction: 'AAAA==' },
    }]);

    await assert.rejects(
      () => fetchChallenge('https://auth.example.com/auth', ACCOUNT_A),
      /missing "network_passphrase"/,
    );
  });
});

// ── Challenge response validation: verifyChallenge ───────────────────────────

describe('verifyChallenge', () => {
  let originalFetch;
  before(() => { originalFetch = global.fetch; });
  afterEach(() => { global.fetch = originalFetch; });

  it('POSTs the signed XDR as JSON body', async () => {
    let capturedOpts;
    global.fetch = async (_url, opts) => {
      capturedOpts = opts;
      return {
        ok:   true,
        json: async () => ({ token: 'jwt.token.here' }),
        text: async () => '',
      };
    };

    await verifyChallenge('https://auth.example.com/auth', 'SIGNED_XDR');
    assert.strictEqual(capturedOpts.method, 'POST');
    const body = JSON.parse(capturedOpts.body);
    assert.strictEqual(body.transaction, 'SIGNED_XDR');
  });

  it('returns the JWT on success', async () => {
    global.fetch = makeFetchMock([{ body: { token: 'my.jwt.here' } }]);

    const token = await verifyChallenge('https://auth.example.com/auth', 'SIGNED_XDR');
    assert.strictEqual(token, 'my.jwt.here');
  });

  it('throws on non-200 response', async () => {
    global.fetch = makeFetchMock([{ ok: false, status: 400, body: 'Bad Request' }]);

    await assert.rejects(
      () => verifyChallenge('https://auth.example.com/auth', 'BAD_XDR'),
      (err) => {
        assert.ok(err.message.includes('400'));
        return true;
      },
    );
  });

  it('throws when token field is missing from response', async () => {
    global.fetch = makeFetchMock([{ body: { message: 'ok but no token' } }]);

    await assert.rejects(
      () => verifyChallenge('https://auth.example.com/auth', 'XDR'),
      /missing "token"/,
    );
  });
});

// ── getAuthToken (full challenge + verify cycle) ──────────────────────────────

describe('getAuthToken', () => {
  let originalFetch;
  before(() => { originalFetch = global.fetch; });
  afterEach(() => { global.fetch = originalFetch; });

  it('calls fetchChallenge then verifyChallenge and returns a token', async () => {
    let callCount = 0;
    global.fetch = async (url, opts) => {
      callCount++;
      if (!opts || opts.method === 'GET') {
        return {
          ok:   true,
          json: async () => ({
            transaction:        'CHALLENGE_XDR',
            network_passphrase: 'Test SDF Network ; September 2015',
          }),
          text: async () => '',
        };
      }
      // POST
      return {
        ok:   true,
        json: async () => ({ token: 'final.jwt' }),
        text: async () => '',
      };
    };

    const signerFn = async (xdr, _passphrase) => `SIGNED::${xdr}`;
    const token = await getAuthToken('https://auth.example.com/auth', ACCOUNT_A, signerFn);

    assert.strictEqual(token, 'final.jwt');
    assert.strictEqual(callCount, 2); // one GET, one POST
  });

  it('propagates signer errors', async () => {
    global.fetch = makeFetchMock([{
      body: {
        transaction:        'XDR',
        network_passphrase: 'Test',
      },
    }]);

    const signerFn = async () => { throw new Error('User rejected signing'); };

    await assert.rejects(
      () => getAuthToken('https://auth.example.com/auth', ACCOUNT_A, signerFn),
      /User rejected signing/,
    );
  });
});

// ── Freighter auth path ───────────────────────────────────────────────────────

describe('Freighter auth path', () => {
  let originalFetch;
  let originalWindow;

  before(() => {
    originalFetch  = global.fetch;
    originalWindow = global.window;
  });
  afterEach(() => {
    global.fetch  = originalFetch;
    global.window = originalWindow;
    resetStorage();
  });

  it('authenticate() uses cached token without calling Freighter', async () => {
    storeToken(ACCOUNT_A, 'cached.jwt');
    // No fetch or wallet needed
    const result = await authenticate(ACCOUNT_A, SUPPORTED_WALLETS.FREIGHTER);
    assert.strictEqual(result.token, 'cached.jwt');
    assert.strictEqual(result.fromCache, true);
  });

  it('authenticate() in demo mode returns a demo token without contacting Freighter', async () => {
    // Ensure no endpoint is configured
    delete global.window.LUMENFLOW_WEB_AUTH_ENDPOINT;
    resetStorage();

    const result = await authenticate(ACCOUNT_A, SUPPORTED_WALLETS.FREIGHTER);
    assert.ok(result.token);
    assert.ok(result.token.endsWith('.demo-signature'));
    assert.strictEqual(result.fromCache, false);
  });

  it('authenticate() with Freighter calls the SEP-0010 flow', async () => {
    // Set up a fake web-auth endpoint
    global.window.LUMENFLOW_WEB_AUTH_ENDPOINT = 'https://auth.example.com/auth';
    resetStorage();

    // Mock fetch: GET returns challenge, POST returns token
    global.fetch = async (_url, opts) => {
      if (!opts || opts.method !== 'POST') {
        return {
          ok:   true,
          json: async () => ({
            transaction:        'CHALLENGE_XDR',
            network_passphrase: 'Test SDF Network ; September 2015',
          }),
          text: async () => '',
        };
      }
      return {
        ok:   true,
        json: async () => ({ token: 'freighter.jwt' }),
        text: async () => '',
      };
    };

    // Mock Freighter API on window
    global.window.freighterApi = {
      isConnected:     async () => true,
      signTransaction: async (xdr, _opts) => `SIGNED::${xdr}`,
    };

    const result = await authenticate(ACCOUNT_A, SUPPORTED_WALLETS.FREIGHTER);
    assert.strictEqual(result.token, 'freighter.jwt');
    assert.strictEqual(result.fromCache, false);

    // Token should now be cached
    assert.strictEqual(getStoredToken(ACCOUNT_A), 'freighter.jwt');

    // Clean up
    delete global.window.LUMENFLOW_WEB_AUTH_ENDPOINT;
    delete global.window.freighterApi;
  });

  it('authenticate() throws when Freighter is not installed', async () => {
    global.window.LUMENFLOW_WEB_AUTH_ENDPOINT = 'https://auth.example.com/auth';
    resetStorage();

    // Provide challenge so we get to the signing step
    global.fetch = makeFetchMock([{
      body: {
        transaction:        'XDR',
        network_passphrase: 'Test',
      },
    }]);

    // No freighterApi on window
    delete global.window.freighterApi;
    global.window.isFreighterInstalled = false;

    await assert.rejects(
      () => authenticate(ACCOUNT_A, SUPPORTED_WALLETS.FREIGHTER),
      /Freighter wallet is not installed/,
    );

    delete global.window.LUMENFLOW_WEB_AUTH_ENDPOINT;
  });
});

// ── SEP-0010 auth path (generic) ──────────────────────────────────────────────

describe('SEP-0010 auth path', () => {
  let originalFetch;
  let originalWindow;

  before(() => {
    originalFetch  = global.fetch;
    originalWindow = global.window;
  });
  afterEach(() => {
    global.fetch  = originalFetch;
    global.window = originalWindow;
    resetStorage();
  });

  it('full SEP-0010 round-trip: challenge → sign → token → cache', async () => {
    global.window.LUMENFLOW_WEB_AUTH_ENDPOINT = 'https://sep10.example.com/auth';
    resetStorage();

    const expectedToken = 'sep0010.jwt.signed';
    let postBody;

    global.fetch = async (url, opts) => {
      if (!opts || !opts.method || opts.method === 'GET') {
        return {
          ok:   true,
          json: async () => ({
            transaction:        'ORIGINAL_XDR',
            network_passphrase: 'Public Global Stellar Network ; September 2015',
          }),
          text: async () => '',
        };
      }
      // POST
      postBody = JSON.parse(opts.body);
      return {
        ok:   true,
        json: async () => ({ token: expectedToken }),
        text: async () => '',
      };
    };

    global.window.freighterApi = {
      isConnected:     async () => true,
      signTransaction: async (xdr, _opts) => `SIGNED_MAINNET_XDR::${xdr}`,
    };

    const result = await authenticate(ACCOUNT_B, SUPPORTED_WALLETS.FREIGHTER);

    // Verify the signed XDR was POSTed correctly
    assert.strictEqual(postBody.transaction, 'SIGNED_MAINNET_XDR::ORIGINAL_XDR');
    assert.strictEqual(result.token, expectedToken);
    assert.strictEqual(result.fromCache, false);

    // Second call should return from cache
    const cached = await authenticate(ACCOUNT_B, SUPPORTED_WALLETS.FREIGHTER);
    assert.strictEqual(cached.token, expectedToken);
    assert.strictEqual(cached.fromCache, true);

    delete global.window.LUMENFLOW_WEB_AUTH_ENDPOINT;
    delete global.window.freighterApi;
  });

  it('authenticate() rejects invalid account addresses', async () => {
    await assert.rejects(
      () => authenticate('not-a-stellar-address', SUPPORTED_WALLETS.FREIGHTER),
      /valid Stellar account address/,
    );
  });

  it('authenticate() rejects unsupported wallet types', async () => {
    global.window.LUMENFLOW_WEB_AUTH_ENDPOINT = 'https://sep10.example.com/auth';
    global.fetch = makeFetchMock([{
      body: {
        transaction:        'XDR',
        network_passphrase: 'Test',
      },
    }]);

    await assert.rejects(
      () => authenticate(ACCOUNT_A, 'phantom'),
      /Unsupported wallet type/,
    );

    delete global.window.LUMENFLOW_WEB_AUTH_ENDPOINT;
  });
});

// ── LOBSTR wallet compatibility ───────────────────────────────────────────────

describe('LOBSTR wallet compatibility', () => {
  let originalFetch;
  let originalWindow;

  before(() => {
    originalFetch  = global.fetch;
    originalWindow = global.window;
  });
  afterEach(() => {
    global.fetch  = originalFetch;
    global.window = originalWindow;
    resetStorage();
  });

  /**
   * Note: LOBSTR Vault exposes window.lobstr.signTransaction(xdr, opts).
   * The response shape is { signedXdr: string } or a plain string.
   * Full compatibility requires the LOBSTR Vault browser extension ≥ v2.
   * Mobile deep-link flow is not tested here (requires native app).
   */

  it('authenticate() with LOBSTR calls window.lobstr.signTransaction', async () => {
    global.window.LUMENFLOW_WEB_AUTH_ENDPOINT = 'https://auth.example.com/auth';
    resetStorage();

    global.fetch = async (_url, opts) => {
      if (!opts || opts.method !== 'POST') {
        return {
          ok:   true,
          json: async () => ({
            transaction:        'LOBSTR_CHALLENGE_XDR',
            network_passphrase: 'Test SDF Network ; September 2015',
          }),
          text: async () => '',
        };
      }
      return {
        ok:   true,
        json: async () => ({ token: 'lobstr.jwt' }),
        text: async () => '',
      };
    };

    global.window.lobstr = {
      signTransaction: async (xdr, _opts) => ({ signedXdr: `LOBSTR_SIGNED::${xdr}` }),
    };

    const result = await authenticate(ACCOUNT_A, SUPPORTED_WALLETS.LOBSTR);
    assert.strictEqual(result.token, 'lobstr.jwt');

    delete global.window.LUMENFLOW_WEB_AUTH_ENDPOINT;
    delete global.window.lobstr;
  });

  it('throws when LOBSTR wallet is not available', async () => {
    global.window.LUMENFLOW_WEB_AUTH_ENDPOINT = 'https://auth.example.com/auth';
    global.fetch = makeFetchMock([{
      body: {
        transaction:        'XDR',
        network_passphrase: 'Test',
      },
    }]);
    delete global.window.lobstr;

    await assert.rejects(
      () => authenticate(ACCOUNT_A, SUPPORTED_WALLETS.LOBSTR),
      /LOBSTR wallet is not available/,
    );

    delete global.window.LUMENFLOW_WEB_AUTH_ENDPOINT;
  });
});

// ── Solar Wallet compatibility ────────────────────────────────────────────────

describe('Solar Wallet compatibility', () => {
  let originalFetch;
  let originalWindow;

  before(() => {
    originalFetch  = global.fetch;
    originalWindow = global.window;
  });
  afterEach(() => {
    global.fetch  = originalFetch;
    global.window = originalWindow;
    resetStorage();
  });

  /**
   * Note: Solar Wallet exposes window.solarWallet.signTransaction(xdr, opts).
   * The response shape is { signedXdr: string } or a plain string.
   * Solar Wallet follows the SEP-0007 URI scheme for mobile signing.
   * See https://solarwallet.io for extension installation.
   */

  it('authenticate() with Solar Wallet calls window.solarWallet.signTransaction', async () => {
    global.window.LUMENFLOW_WEB_AUTH_ENDPOINT = 'https://auth.example.com/auth';
    resetStorage();

    global.fetch = async (_url, opts) => {
      if (!opts || opts.method !== 'POST') {
        return {
          ok:   true,
          json: async () => ({
            transaction:        'SOLAR_CHALLENGE_XDR',
            network_passphrase: 'Test SDF Network ; September 2015',
          }),
          text: async () => '',
        };
      }
      return {
        ok:   true,
        json: async () => ({ token: 'solar.jwt' }),
        text: async () => '',
      };
    };

    global.window.solarWallet = {
      signTransaction: async (xdr, _opts) => `SOLAR_SIGNED::${xdr}`,
    };

    const result = await authenticate(ACCOUNT_A, SUPPORTED_WALLETS.SOLAR);
    assert.strictEqual(result.token, 'solar.jwt');

    delete global.window.LUMENFLOW_WEB_AUTH_ENDPOINT;
    delete global.window.solarWallet;
  });

  it('throws when Solar Wallet is not available', async () => {
    global.window.LUMENFLOW_WEB_AUTH_ENDPOINT = 'https://auth.example.com/auth';
    global.fetch = makeFetchMock([{
      body: {
        transaction:        'XDR',
        network_passphrase: 'Test',
      },
    }]);
    delete global.window.solarWallet;

    await assert.rejects(
      () => authenticate(ACCOUNT_A, SUPPORTED_WALLETS.SOLAR),
      /Solar Wallet is not available/,
    );

    delete global.window.LUMENFLOW_WEB_AUTH_ENDPOINT;
  });
});

// ── Demo token (_buildDemoToken) ──────────────────────────────────────────────

describe('_buildDemoToken', () => {
  it('returns a three-part JWT-like string', () => {
    const token = _buildDemoToken(ACCOUNT_A);
    const parts = token.split('.');
    assert.strictEqual(parts.length, 3);
  });

  it('encodes the account address in the payload', () => {
    const token = _buildDemoToken(ACCOUNT_A);
    const payloadB64 = token.split('.')[1];
    // Re-pad the base64url string
    const padded = payloadB64.replace(/-/g, '+').replace(/_/g, '/') +
      '=='.slice(0, (4 - (payloadB64.length % 4)) % 4);
    const payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
    assert.strictEqual(payload.sub, ACCOUNT_A);
    assert.strictEqual(payload.demo, true);
  });

  it('sets expiry ~24 hours in the future', () => {
    const before = Math.floor(Date.now() / 1000);
    const token  = _buildDemoToken(ACCOUNT_A);
    const after  = Math.floor(Date.now() / 1000);

    const payloadB64 = token.split('.')[1];
    const padded = payloadB64.replace(/-/g, '+').replace(/_/g, '/') +
      '=='.slice(0, (4 - (payloadB64.length % 4)) % 4);
    const payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));

    const expectedTTL = Math.floor(JWT_TTL_MS / 1000);
    assert.ok(payload.exp >= before + expectedTTL);
    assert.ok(payload.exp <= after  + expectedTTL + 2); // 2s tolerance
  });

  it('ends with .demo-signature sentinel', () => {
    const token = _buildDemoToken(ACCOUNT_A);
    assert.ok(token.endsWith('.demo-signature'));
  });
});
