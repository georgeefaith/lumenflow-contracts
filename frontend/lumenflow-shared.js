/**
 * lumenflow-shared.js
 *
 * Shared authentication utilities for LumenFlow frontend pages.
 *
 * Implements Stellar SEP-0010 Web Authentication:
 *   https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md
 *
 * Flow:
 *   1. GET  {WEB_AUTH_ENDPOINT}?account={account}  → challenge XDR
 *   2. Sign the challenge transaction via the wallet
 *   3. POST signed XDR back to the endpoint          → JWT
 *   4. Cache the JWT in sessionStorage (24-hour TTY)
 *
 * Exports (available as window.LumenFlowAuth in browser, or via module syntax):
 *   authenticate(account, walletType)  – full SEP-0010 flow
 *   getStoredToken(account)            – retrieve cached JWT if still valid
 *   clearToken(account)                – remove cached JWT
 *   SUPPORTED_WALLETS                  – list of supported wallet identifiers
 */

// ── Constants ─────────────────────────────────────────────────────────────────

/** Wallet identifiers supported by this module. */
const SUPPORTED_WALLETS = Object.freeze({
  FREIGHTER: 'freighter',
  LOBSTR:    'lobstr',
  SOLAR:     'solar',
});

/** SessionStorage key template for cached JWTs. */
const JWT_STORAGE_KEY = (account) => `lumenflow_jwt_${account}`;

/** JWT cache TTL in milliseconds (24 hours). */
const JWT_TTL_MS = 24 * 60 * 60 * 1000;

// ── Configuration ─────────────────────────────────────────────────────────────

/**
 * Resolve the SEP-0010 web-auth endpoint.
 *
 * Priority:
 *   1. window.LUMENFLOW_WEB_AUTH_ENDPOINT  (injected by the page/server)
 *   2. LUMENFLOW_WEB_AUTH_ENDPOINT env var  (build-time injection)
 *   3. Derived from the current origin (assumes the auth service is co-hosted)
 *
 * For local development / demo mode the function returns null so callers
 * can fall back to mock behaviour.
 */
function getWebAuthEndpoint() {
  if (typeof window !== 'undefined' && window.LUMENFLOW_WEB_AUTH_ENDPOINT) {
    return window.LUMENFLOW_WEB_AUTH_ENDPOINT;
  }
  // Injected at build time by a bundler (optional)
  if (typeof LUMENFLOW_WEB_AUTH_ENDPOINT !== 'undefined') {
    // eslint-disable-next-line no-undef
    return LUMENFLOW_WEB_AUTH_ENDPOINT;
  }
  return null; // demo / fallback
}

// ── Token cache helpers ───────────────────────────────────────────────────────

/**
 * Persist a JWT with an expiry timestamp.
 *
 * @param {string} account  Stellar account address (G…)
 * @param {string} token    JWT string
 */
function storeToken(account, token) {
  if (typeof sessionStorage === 'undefined') return;
  const payload = JSON.stringify({ token, expiresAt: Date.now() + JWT_TTL_MS });
  sessionStorage.setItem(JWT_STORAGE_KEY(account), payload);
}

/**
 * Retrieve a cached JWT if it has not yet expired.
 *
 * @param {string} account  Stellar account address (G…)
 * @returns {string|null}   JWT string, or null if absent / expired
 */
function getStoredToken(account) {
  if (typeof sessionStorage === 'undefined') return null;
  const raw = sessionStorage.getItem(JWT_STORAGE_KEY(account));
  if (!raw) return null;
  try {
    const { token, expiresAt } = JSON.parse(raw);
    if (Date.now() >= expiresAt) {
      sessionStorage.removeItem(JWT_STORAGE_KEY(account));
      return null;
    }
    return token;
  } catch {
    sessionStorage.removeItem(JWT_STORAGE_KEY(account));
    return null;
  }
}

/**
 * Remove a cached JWT for the given account.
 *
 * @param {string} account  Stellar account address (G…)
 */
function clearToken(account) {
  if (typeof sessionStorage === 'undefined') return;
  sessionStorage.removeItem(JWT_STORAGE_KEY(account));
}

// ── SEP-0010 challenge helpers ────────────────────────────────────────────────

/**
 * Fetch the SEP-0010 challenge transaction from the auth server.
 *
 * @param {string} webAuthEndpoint  Base URL of the SEP-0010 endpoint
 * @param {string} account          Stellar account address (G…)
 * @returns {Promise<{transaction: string, network_passphrase: string}>}
 * @throws  {Error} on network error or non-200 response
 */
async function fetchChallenge(webAuthEndpoint, account) {
  const url = new URL(webAuthEndpoint);
  url.searchParams.set('account', account);

  const response = await fetch(url.toString(), {
    method:  'GET',
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(
      `SEP-0010 challenge fetch failed (HTTP ${response.status}): ${body || response.statusText}`,
    );
  }

  const data = await response.json();

  if (!data.transaction) {
    throw new Error('SEP-0010 challenge response missing "transaction" field');
  }
  if (!data.network_passphrase) {
    throw new Error('SEP-0010 challenge response missing "network_passphrase" field');
  }

  return { transaction: data.transaction, network_passphrase: data.network_passphrase };
}

/**
 * Submit the signed challenge XDR and retrieve a JWT.
 *
 * @param {string} webAuthEndpoint  Base URL of the SEP-0010 endpoint
 * @param {string} signedXdr        Base64-encoded signed transaction XDR
 * @returns {Promise<string>}       JWT token
 * @throws  {Error} on network error, non-200 response, or missing token
 */
async function verifyChallenge(webAuthEndpoint, signedXdr) {
  const response = await fetch(webAuthEndpoint, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body:    JSON.stringify({ transaction: signedXdr }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(
      `SEP-0010 token request failed (HTTP ${response.status}): ${body || response.statusText}`,
    );
  }

  const data = await response.json();

  if (!data.token) {
    throw new Error('SEP-0010 auth response missing "token" field');
  }

  return data.token;
}

/**
 * High-level helper: complete the full SEP-0010 challenge/response cycle.
 *
 * @param {string} webAuthEndpoint  Base URL of the SEP-0010 endpoint
 * @param {string} account          Stellar account address
 * @param {Function} signerFn       Async function that accepts (xdr, networkPassphrase)
 *                                  and returns the signed XDR string
 * @returns {Promise<string>}       JWT token
 */
async function getAuthToken(webAuthEndpoint, account, signerFn) {
  const { transaction, network_passphrase } = await fetchChallenge(webAuthEndpoint, account);
  const signedXdr = await signerFn(transaction, network_passphrase);
  return verifyChallenge(webAuthEndpoint, signedXdr);
}

// ── Wallet adapters ───────────────────────────────────────────────────────────

/**
 * Sign a transaction XDR using the Freighter browser extension.
 *
 * Freighter API reference: https://docs.freighter.app/docs/guide/usingFreighterBrowser
 *
 * @param {string} xdr               Base64-encoded unsigned transaction XDR
 * @param {string} networkPassphrase Stellar network passphrase
 * @returns {Promise<string>}        Signed XDR string
 * @throws  {Error} if Freighter is not installed or the user rejects the request
 */
async function signWithFreighter(xdr, networkPassphrase) {
  // Freighter injects window.freighterApi in newer versions, and also exposes
  // the top-level functions directly on window for older versions.
  const api =
    (typeof window !== 'undefined' && window.freighterApi) ||
    (typeof window !== 'undefined' && window.isFreighterInstalled && window);

  if (!api) {
    throw new Error(
      'Freighter wallet is not installed. ' +
      'Please install the Freighter extension from https://www.freighter.app/',
    );
  }

  const isConnected = await api.isConnected();
  if (!isConnected) {
    throw new Error('Freighter is not connected. Please unlock your Freighter wallet.');
  }

  // signTransaction returns the signed XDR string directly in Freighter ≥ 1.x
  const result = await api.signTransaction(xdr, { networkPassphrase });

  // Newer Freighter versions return { signedTxXdr, signerAddress }
  if (result && typeof result === 'object' && result.signedTxXdr) {
    return result.signedTxXdr;
  }

  // Older versions return the XDR string directly
  if (typeof result === 'string') {
    return result;
  }

  throw new Error('Freighter returned an unexpected response format.');
}

/**
 * Sign a transaction XDR using the LOBSTR wallet.
 *
 * LOBSTR exposes a window.lobstr object with a signTransaction method.
 * Compatibility: LOBSTR Vault browser extension and LOBSTR mobile deep-link.
 *
 * @param {string} xdr               Base64-encoded unsigned transaction XDR
 * @param {string} networkPassphrase Stellar network passphrase
 * @returns {Promise<string>}        Signed XDR string
 * @throws  {Error} if LOBSTR is not available
 */
async function signWithLobstr(xdr, networkPassphrase) {
  if (typeof window === 'undefined' || !window.lobstr) {
    throw new Error(
      'LOBSTR wallet is not available. ' +
      'Please install the LOBSTR Vault extension or use the LOBSTR mobile app.',
    );
  }

  const result = await window.lobstr.signTransaction(xdr, { networkPassphrase });

  if (result && typeof result === 'object' && result.signedXdr) {
    return result.signedXdr;
  }
  if (typeof result === 'string') {
    return result;
  }

  throw new Error('LOBSTR returned an unexpected response format.');
}

/**
 * Sign a transaction XDR using the Solar Wallet.
 *
 * Solar Wallet follows the SEP-0007 URI scheme and exposes a
 * window.solarWallet object with a signTransaction method.
 *
 * @param {string} xdr               Base64-encoded unsigned transaction XDR
 * @param {string} networkPassphrase Stellar network passphrase
 * @returns {Promise<string>}        Signed XDR string
 * @throws  {Error} if Solar Wallet is not available
 */
async function signWithSolar(xdr, networkPassphrase) {
  if (typeof window === 'undefined' || !window.solarWallet) {
    throw new Error(
      'Solar Wallet is not available. ' +
      'Please install Solar Wallet from https://solarwallet.io/',
    );
  }

  const result = await window.solarWallet.signTransaction(xdr, { networkPassphrase });

  if (result && typeof result === 'object' && result.signedXdr) {
    return result.signedXdr;
  }
  if (typeof result === 'string') {
    return result;
  }

  throw new Error('Solar Wallet returned an unexpected response format.');
}

/**
 * Return the wallet-specific signer function for the given wallet type.
 *
 * @param {string} walletType  One of the SUPPORTED_WALLETS values
 * @returns {Function}         Async signer: (xdr, networkPassphrase) => signedXdr
 */
function getSignerForWallet(walletType) {
  switch (walletType) {
    case SUPPORTED_WALLETS.FREIGHTER:
      return signWithFreighter;
    case SUPPORTED_WALLETS.LOBSTR:
      return signWithLobstr;
    case SUPPORTED_WALLETS.SOLAR:
      return signWithSolar;
    default:
      throw new Error(
        `Unsupported wallet type: "${walletType}". ` +
        `Supported wallets: ${Object.values(SUPPORTED_WALLETS).join(', ')}`,
      );
  }
}

// ── Unified authenticate() ────────────────────────────────────────────────────

/**
 * Authenticate a Stellar account using SEP-0010 Web Authentication.
 *
 * Workflow:
 *   1. Return the cached JWT if it is still valid.
 *   2. Otherwise run the full SEP-0010 challenge/response flow using the
 *      specified wallet to sign the challenge transaction.
 *   3. Cache and return the fresh JWT.
 *
 * @param {string} account     Stellar account address (G…)
 * @param {string} walletType  Wallet identifier from SUPPORTED_WALLETS
 *                             Defaults to SUPPORTED_WALLETS.FREIGHTER
 * @returns {Promise<{token: string, fromCache: boolean}>}
 * @throws  {Error} if authentication fails at any step
 *
 * @example
 * const { token } = await authenticate('GABC…', 'freighter');
 * // Use token in Authorization header: `Bearer ${token}`
 */
async function authenticate(account, walletType = SUPPORTED_WALLETS.FREIGHTER) {
  if (!account || typeof account !== 'string' || !account.startsWith('G')) {
    throw new Error('authenticate() requires a valid Stellar account address (G…)');
  }

  // 1. Return cached token if still valid
  const cached = getStoredToken(account);
  if (cached) {
    return { token: cached, fromCache: true };
  }

  const webAuthEndpoint = getWebAuthEndpoint();

  // 2. Demo / no-endpoint mode — return a synthetic demo token so pages
  //    can work without a live auth server during local development.
  if (!webAuthEndpoint) {
    const demoToken = _buildDemoToken(account);
    storeToken(account, demoToken);
    return { token: demoToken, fromCache: false };
  }

  // 3. Resolve the signer for the requested wallet
  const signerFn = getSignerForWallet(walletType);

  // 4. Full SEP-0010 challenge/response flow
  const token = await getAuthToken(webAuthEndpoint, account, signerFn);

  // 5. Cache and return
  storeToken(account, token);
  return { token, fromCache: false };
}

// ── Demo token helper (development only) ─────────────────────────────────────

/**
 * Build a minimal, unsigned demo JWT for local development.
 *
 * WARNING: This is NOT a valid JWT for production use. It is returned only
 * when no LUMENFLOW_WEB_AUTH_ENDPOINT is configured so that the UI can
 * render without a live auth server.
 *
 * @param {string} account  Stellar account address
 * @returns {string}        Fake JWT string
 */
function _buildDemoToken(account) {
  const header  = _b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payload = _b64url(
    JSON.stringify({
      sub:  account,
      iss:  'lumenflow-demo',
      iat:  Math.floor(Date.now() / 1000),
      exp:  Math.floor((Date.now() + JWT_TTL_MS) / 1000),
      demo: true,
    }),
  );
  return `${header}.${payload}.demo-signature`;
}

/**
 * Base64url-encode a UTF-8 string.
 *
 * @param {string} str
 * @returns {string}
 */
function _b64url(str) {
  if (typeof btoa !== 'undefined') {
    return btoa(unescape(encodeURIComponent(str)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  // Node.js (tests)
  return Buffer.from(str, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// ── Exports ───────────────────────────────────────────────────────────────────

// CommonJS (Node.js / Jest)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    authenticate,
    getStoredToken,
    clearToken,
    storeToken,       // exported for tests
    fetchChallenge,   // exported for tests
    verifyChallenge,  // exported for tests
    getAuthToken,     // exported for tests
    SUPPORTED_WALLETS,
    JWT_STORAGE_KEY,
    JWT_TTL_MS,
    _buildDemoToken,  // exported for tests
    _b64url,          // exported for tests
  };
}

// Browser global (no bundler)
if (typeof window !== 'undefined') {
  window.LumenFlowAuth = {
    authenticate,
    getStoredToken,
    clearToken,
    SUPPORTED_WALLETS,
  };
}
