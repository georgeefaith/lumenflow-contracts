/**
 * LumenFlow i18n — plain browser-side internationalisation module.
 *
 * Usage:
 *   <script src="i18n/i18n.js"></script>
 *   <span data-i18n="table.date">Date</span>
 *
 * The module auto-detects the user's preferred language from navigator.language,
 * persists the choice in localStorage under the key 'lumenflow_lang', and exposes
 * four functions on the global window.LumenFlowI18n object:
 *
 *   t(key, fallback?)      – look up a translation key; return fallback or key on miss
 *   setLanguage(lang)      – change language and re-apply translations to the DOM
 *   applyTranslations()    – iterate [data-i18n] elements and set their textContent
 *   getCurrentLanguage()   – return the currently active language code
 */

(function () {
  'use strict';

  // ── Constants ───────────────────────────────────────────────────────────────

  const STORAGE_KEY   = 'lumenflow_lang';
  const DEFAULT_LANG  = 'en';
  const SUPPORTED     = ['en', 'es'];

  // Base path for JSON files — relative to the HTML page that loads this script.
  // If your HTML files live in a sub-directory, override window.LUMENFLOW_I18N_BASE
  // before loading this script.
  const BASE_PATH = (typeof window !== 'undefined' && window.LUMENFLOW_I18N_BASE)
    ? window.LUMENFLOW_I18N_BASE
    : 'i18n/';

  // ── State ───────────────────────────────────────────────────────────────────

  // Lazy-loaded cache: { en: {...}, es: {...} }
  const _cache = {};

  // Currently active language code.
  let _lang = DEFAULT_LANG;

  // ── Language detection ──────────────────────────────────────────────────────

  /**
   * Determine the initial language:
   *  1. Persisted preference in localStorage
   *  2. Browser's navigator.language (first segment before '-')
   *  3. Fall back to DEFAULT_LANG
   */
  function _detectLanguage() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored && SUPPORTED.includes(stored)) return stored;
    } catch (_) {
      // localStorage unavailable (e.g. private browsing with strict settings)
    }

    if (typeof navigator !== 'undefined' && navigator.language) {
      const browserLang = navigator.language.split('-')[0].toLowerCase();
      if (SUPPORTED.includes(browserLang)) return browserLang;
    }

    return DEFAULT_LANG;
  }

  // ── JSON loader ─────────────────────────────────────────────────────────────

  /**
   * Load the JSON translation file for `lang` if not already cached.
   * Returns a Promise that resolves to the translations object.
   */
  async function _load(lang) {
    if (_cache[lang]) return _cache[lang];

    try {
      const response = await fetch(BASE_PATH + lang + '.json');
      if (!response.ok) {
        console.warn('[i18n] Could not load translations for "' + lang + '": HTTP ' + response.status);
        _cache[lang] = {};
        return _cache[lang];
      }
      _cache[lang] = await response.json();
    } catch (err) {
      console.warn('[i18n] Failed to parse translations for "' + lang + '":', err);
      _cache[lang] = {};
    }

    return _cache[lang];
  }

  // ── Key resolution ──────────────────────────────────────────────────────────

  /**
   * Resolve a dot-notation key against a flat/nested object.
   * e.g. get({ table: { date: 'Date' } }, 'table.date') => 'Date'
   */
  function _resolve(obj, key) {
    if (!obj || typeof obj !== 'object') return undefined;
    const parts = key.split('.');
    let current = obj;
    for (const part of parts) {
      if (current === null || typeof current !== 'object' || !(part in current)) {
        return undefined;
      }
      current = current[part];
    }
    return typeof current === 'string' ? current : undefined;
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Return the translated string for `key` in the currently active language.
   *
   * Lookup order:
   *  1. Active language cache
   *  2. English fallback cache (if active language is not English)
   *  3. `fallback` argument (if provided)
   *  4. The key itself
   *
   * @param {string} key      - Dot-notation translation key (e.g. 'table.date')
   * @param {string} [fallback] - Optional fallback string
   * @returns {string}
   */
  function t(key, fallback) {
    const activeTrans = _cache[_lang];
    if (activeTrans) {
      const val = _resolve(activeTrans, key);
      if (val !== undefined) return val;
    }

    // Try English fallback when active language is not English
    if (_lang !== DEFAULT_LANG && _cache[DEFAULT_LANG]) {
      const enVal = _resolve(_cache[DEFAULT_LANG], key);
      if (enVal !== undefined) return enVal;
    }

    // Provided fallback or the key itself
    return fallback !== undefined ? fallback : key;
  }

  /**
   * Return the currently active language code.
   * @returns {string}
   */
  function getCurrentLanguage() {
    return _lang;
  }

  /**
   * Iterate every DOM element that has a [data-i18n] attribute and replace
   * its textContent with the translated string.
   *
   * Elements that also carry [data-i18n-attr] will have that HTML attribute
   * set instead of (or in addition to) textContent.
   * e.g. <input data-i18n="filter.amountMin" data-i18n-attr="placeholder" />
   */
  function applyTranslations() {
    if (typeof document === 'undefined') return;

    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      const key      = el.getAttribute('data-i18n');
      const attrName = el.getAttribute('data-i18n-attr');
      const value    = t(key);

      if (attrName) {
        el.setAttribute(attrName, value);
      } else {
        el.textContent = value;
      }
    });

    // Update <html lang="…"> for accessibility
    if (document.documentElement) {
      document.documentElement.setAttribute('lang', _lang);
    }

    // Sync the language selector if one exists on the page
    const selector = document.getElementById('lang-selector');
    if (selector && selector.value !== _lang) {
      selector.value = _lang;
    }
  }

  /**
   * Change the active language, persist the choice, load translations if needed,
   * then re-apply all translations to the DOM.
   *
   * @param {string} lang - Language code (e.g. 'en', 'es')
   * @returns {Promise<void>}
   */
  async function setLanguage(lang) {
    const normalized = (lang || DEFAULT_LANG).toLowerCase().split('-')[0];
    const target     = SUPPORTED.includes(normalized) ? normalized : DEFAULT_LANG;

    _lang = target;

    try {
      localStorage.setItem(STORAGE_KEY, target);
    } catch (_) {
      // localStorage unavailable
    }

    await _load(target);

    // Ensure English fallback is also loaded
    if (target !== DEFAULT_LANG) {
      await _load(DEFAULT_LANG);
    }

    applyTranslations();
  }

  // ── Initialisation ──────────────────────────────────────────────────────────

  /**
   * Bootstrap: detect language, load translations, then apply them.
   * Called automatically when the DOM is ready.
   */
  async function _init() {
    _lang = _detectLanguage();

    // Load active language and English fallback in parallel
    const loaders = [_load(_lang)];
    if (_lang !== DEFAULT_LANG) loaders.push(_load(DEFAULT_LANG));
    await Promise.all(loaders);

    applyTranslations();
  }

  // ── Exports ─────────────────────────────────────────────────────────────────

  const LumenFlowI18n = {
    t,
    setLanguage,
    applyTranslations,
    getCurrentLanguage,
  };

  // Expose on window for plain-script usage
  if (typeof window !== 'undefined') {
    window.LumenFlowI18n = LumenFlowI18n;

    // Also expose the shorthand `t` directly for convenience
    // e.g. t('table.date') instead of LumenFlowI18n.t('table.date')
    window.t = t;
  }

  // ── Auto-init ───────────────────────────────────────────────────────────────

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', _init);
    } else {
      // DOM already ready (script loaded with defer or at bottom of body)
      _init();
    }
  }
})();
