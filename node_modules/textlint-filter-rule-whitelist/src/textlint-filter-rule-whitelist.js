// LICENSE : MIT
"use strict";
const path = require("path");
const rcfile = require("rc-config-loader");
const { getConfigBaseDir } = require("@textlint/get-config-base-dir");
const { matchPatterns } = require("@textlint/regexp-string-matcher");
const getAllowWordsFromFiles = (files, baseDirectory) => {
    let results = [];
    files.forEach(filePath => {
        // TODO: use other loader
        const contents = rcfile("file", {
            configFileName: path.resolve(baseDirectory, filePath)
        });
        if (contents && Array.isArray(contents.config)) {
            results = results.concat(contents.config);
        } else {
            throw new Error(`This allow file is not allow word list: ${filePath}`);
        }
    });
    return results;
};

const defaultOptions = {
    /**
     * White list strings or RegExp-like strings
     *
     * [
     *     "string",
     *     "/\\d+/",
     *     "/^===/m",
     * ]
     */
    allow: [],
    /**
     * file path list that includes allow words.
     */
    whitelistConfigPaths: []
};
module.exports = function(context, options) {
    const { Syntax, shouldIgnore, getSource } = context;
    const baseDirectory = getConfigBaseDir(context) || process.cwd();
    const allowWords = options.allow || defaultOptions.allow;
    const whitelistConfigPaths = options.whitelistConfigPaths
        ? getAllowWordsFromFiles(options.whitelistConfigPaths, baseDirectory)
        : [];
    const allAllowWords = allowWords.concat(whitelistConfigPaths);
    return {
        [Syntax.Document](node) {
            const text = getSource(node);
            const matchResults = matchPatterns(text, allAllowWords);
            matchResults.forEach(result => {
                shouldIgnore([result.startIndex, result.endIndex]);
            });
        }
    };
};
