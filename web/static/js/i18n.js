// Chinese-only frontend text loader. No language detection or switching.
(function () {
    const LANGUAGE = 'zh-CN';
    let translations = {};
    let resolveReady;
    window.i18nReady = new Promise(function (resolve) { resolveReady = resolve; });

    function lookup(key) {
        let value = translations;
        String(key || '').split('.').forEach(function (part) {
            value = value && typeof value === 'object' ? value[part] : undefined;
        });
        return typeof value === 'string' ? value : String(key || '');
    }

    function interpolate(text, options) {
        let result = text;
        if (options && typeof options === 'object') {
            Object.keys(options).forEach(function (key) {
                result = result.split('{{' + key + '}}').join(String(options[key]));
            });
        }
        return result;
    }

    function translate(key, options) {
        return interpolate(lookup(key), options);
    }

    function applyTranslations(root) {
        const container = root || document;
        container.querySelectorAll('[data-i18n]').forEach(function (el) {
            const key = el.getAttribute('data-i18n');
            const text = translate(key);
            if (!key || !text || text === key) return;
            const skipText = el.getAttribute('data-i18n-skip-text') === 'true';
            const isFormControl = el.tagName === 'INPUT' || el.tagName === 'TEXTAREA';
            if (!skipText && !isFormControl && !el.querySelector('*')) el.textContent = text;
            const attrs = el.getAttribute('data-i18n-attr');
            if (attrs) attrs.split(',').map(function (item) { return item.trim(); }).filter(Boolean).forEach(function (attr) { el.setAttribute(attr, text); });
        });
        document.documentElement.lang = LANGUAGE;
    }

    async function init() {
        const response = await fetch('/static/i18n/zh-CN.json', { cache: 'no-cache' });
        if (!response.ok) throw new Error('failed to load Chinese translations');
        translations = await response.json();
        window.t = translate;
        window.applyTranslations = applyTranslations;
        applyTranslations(document);
        resolveReady();
    }

    document.addEventListener('DOMContentLoaded', function () {
        init().catch(function (error) {
            console.error('Failed to initialize Chinese text:', error);
            window.t = function (key) { return String(key || ''); };
            window.applyTranslations = function () {};
            resolveReady();
        });
    });
})();
