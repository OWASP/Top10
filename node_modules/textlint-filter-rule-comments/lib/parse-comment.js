// LICENSE : MIT
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.isHTMLComment = isHTMLComment;
exports.getValuesFromHTMLComment = getValuesFromHTMLComment;
exports.parseListConfig = parseListConfig;
exports.parseRuleIds = parseRuleIds;
var HTML_COMMENT_REGEXP = /<!--((?:.|\s)*?)-->/g;
function isHTMLComment(htmlString) {
    return HTML_COMMENT_REGEXP.test(htmlString);
}

/**
 * get comment value from html comment tag
 * @param {string} commentValue <!-- comment -->
 * @returns {string[]}
 */
function getValuesFromHTMLComment(commentValue) {
    var results = [];
    commentValue.replace(HTML_COMMENT_REGEXP, function (all, comment) {
        results.push(comment);
    });
    return results;
}
/**
 * Parses a config of values separated by comma.
 * @param {string} string The string to parse.
 * @returns {Object} Result map of values and true values
 */
function parseListConfig(string) {
    var items = {};

    // Collapse whitespace around ,
    string = string.replace(/\s*,\s*/g, ",");
    string.split(/,+/).forEach(function (name) {
        name = name.trim();
        if (!name) {
            return;
        }
        items[name] = true;
    });
    return items;
}

/**
 * parse "textlint-enable aRule, bRule" and return ["aRule", "bRule"]
 * @param {string} string
 * @returns {string[]}
 */
function parseRuleIds(string) {
    return Object.keys(parseListConfig(string));
}
//# sourceMappingURL=parse-comment.js.map