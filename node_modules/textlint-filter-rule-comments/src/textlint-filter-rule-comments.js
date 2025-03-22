// LICENSE : MIT
"use strict";
import StatusManager from "./StatusManager";
import {parseRuleIds, getValuesFromHTMLComment, isHTMLComment} from "./parse-comment";
const defaultOptions = {
    // enable comment directive
    // if comment has the value, then enable textlint rule
    "enablingComment": "textlint-enable",
    // disable comment directive
    // if comment has the value, then disable textlint rule
    "disablingComment": "textlint-disable"
};
module.exports = function(context, options = defaultOptions) {
    const {Syntax, shouldIgnore, getSource} = context;

    const enablingComment = options.enablingComment || defaultOptions.enablingComment;
    const disablingComment = options.disablingComment || defaultOptions.disablingComment;

    const content = getSource();
    const statusManager = new StatusManager(content.length);
    // Get comment value
    return {
        /*

This is wrong format.
https://github.com/wooorm/remark treat as one html block.        

<!-- textlint-disable -->
This is ignored.
<!-- textlint-enable -->

should be

<!-- textlint-disable -->

This is ignored.

<!-- textlint-enable -->
         */
        [Syntax.Html](node){
            const nodeValue = getSource(node);
            if (!isHTMLComment(nodeValue)) {
                return;
            }
            const comments = getValuesFromHTMLComment(nodeValue);
            comments.forEach(commentValue => {
                if (commentValue.indexOf(enablingComment) !== -1) {
                    const configValue = commentValue.replace(enablingComment, "");
                    statusManager.enableReporting(node, parseRuleIds(configValue));
                } else if (commentValue.indexOf(disablingComment) !== -1) {
                    const configValue = commentValue.replace(disablingComment, "");
                    statusManager.disableReporting(node, parseRuleIds(configValue));
                }
            });
        },
        [Syntax.Comment](node){
            const commentValue = node.value || "";
            if (commentValue.indexOf(enablingComment) !== -1) {
                const configValue = commentValue.replace(enablingComment, "");
                statusManager.enableReporting(node, parseRuleIds(configValue));
            } else if (commentValue.indexOf(disablingComment) !== -1) {
                const configValue = commentValue.replace(disablingComment, "");
                statusManager.disableReporting(node, parseRuleIds(configValue));
            }
        },
        [`${Syntax.Document}:exit`](){
            const ignoringMessages = statusManager.getIgnoringMessages();
            ignoringMessages.forEach(message => {
                const range = [message.startIndex, message.endIndex];
                shouldIgnore(range, {
                    ruleId: message.ruleId || "*"
                });
            })
        }
    }
};