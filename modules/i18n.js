const fs = require('fs');
const path = require('path');

const DEFAULT_LANG = 'id';
const SUPPORTED_LANGS = ['id', 'en'];
const LOCALES_DIR = path.join(__dirname, '..', 'locales');

const translationsCache = {};
const langCache = new Map();
let translationsLoaded = false;
let getDb = null;

function loadTranslations() {
  if (translationsLoaded) return;
  for (const lang of SUPPORTED_LANGS) {
    try {
      const file = path.join(LOCALES_DIR, `${lang}.json`);
      translationsCache[lang] = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      translationsCache[lang] = {};
    }
  }
  translationsLoaded = true;
}

function normalizeLang(lang) {
  return SUPPORTED_LANGS.includes(lang) ? lang : DEFAULT_LANG;
}

function bindDb(getDbFn) {
  getDb = getDbFn;
}

function getLanguage(userId) {
  if (userId === undefined || userId === null) return DEFAULT_LANG;
  const key = String(userId);
  return langCache.has(key) ? langCache.get(key) : DEFAULT_LANG;
}

function loadUserLanguage(userId) {
  const key = String(userId);
  if (langCache.has(key)) return Promise.resolve(langCache.get(key));
  let lang = DEFAULT_LANG;
  if (!getDb) {
    langCache.set(key, lang);
    return Promise.resolve(lang);
  }
  return new Promise((resolve) => {
    try {
      const db = getDb();
      if (!db) {
        langCache.set(key, lang);
        return resolve(lang);
      }
      db.get('SELECT language FROM users WHERE user_id = ?', [userId], (err, row) => {
        if (err || !row || !row.language) {
          langCache.set(key, lang);
          return resolve(lang);
        }
        lang = normalizeLang(row.language);
        langCache.set(key, lang);
        resolve(lang);
      });
    } catch (err) {
      langCache.set(key, lang);
      resolve(lang);
    }
  });
}

function setLanguage(userId, lang) {
  const normalized = normalizeLang(String(lang || '').toLowerCase());
  const key = String(userId);
  langCache.set(key, normalized);
  if (!getDb) return Promise.resolve(normalized);
  return new Promise((resolve) => {
    try {
      const db = getDb();
      if (!db) return resolve(normalized);
      db.run(
        'INSERT INTO users (user_id, language) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET language = excluded.language',
        [userId, normalized],
        () => resolve(normalized)
      );
    } catch (err) {
      resolve(normalized);
    }
  });
}

function translate(key, lang, vars) {
  loadTranslations();
  let text = translationsCache[normalizeLang(lang)] ? translationsCache[normalizeLang(lang)][key] : undefined;
  if (text === undefined || text === null) {
    text = translationsCache[DEFAULT_LANG] ? translationsCache[DEFAULT_LANG][key] : undefined;
  }
  if (text === undefined || text === null) {
    return key;
  }
  if (vars && typeof vars === 'object') {
    for (const [k, v] of Object.entries(vars)) {
      text = String(text).split(`{${k}}`).join(String(v));
    }
  }
  return text;
}

function t(userId, key, vars) {
  return translate(key, getLanguage(userId), vars);
}

module.exports = {
  DEFAULT_LANG,
  SUPPORTED_LANGS,
  bindDb,
  getLanguage,
  loadUserLanguage,
  setLanguage,
  translate,
  t,
};