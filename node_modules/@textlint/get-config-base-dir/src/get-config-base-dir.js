// MIT © 2017 azu
"use strict";
const path = require("path");
/**
 * Get config base dir from Context.
 * If you use textlint^9.0.0, use native Context#getConfigBaseDir.
 * If you use textlint < 9.0.0, fallback method
 * @see https://github.com/textlint/textlint/releases/tag/textlint%409.0.0
 * @param {*} context
 * @returns {string|undefined}
 */
export const getConfigBaseDir = context => {
    if (typeof context.getConfigBaseDir === "function") {
        return context.getConfigBaseDir();
    }
    // Old fallback that use deprecated `config` value
    // https://github.com/textlint/textlint/issues/294
    const textlintRcFilePath = context.config ? context.config.configFile : null;
    // .textlinrc directory
    return textlintRcFilePath ? path.dirname(textlintRcFilePath) : undefined;
};
