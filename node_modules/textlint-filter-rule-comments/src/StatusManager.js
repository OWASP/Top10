// LICENSE : MIT
"use strict";
export default class StatusManager {
    constructor(endIndex) {
        /**
         * @typedef {Object} IgnoringCommentObject
         * @property {number|null} startIndex
         * @property {number|null} endIndex
         * @property {string|null} ruleId
         */
        /**
         * @type {IgnoringCommentObject[]}
         */
        this.reportingConfig = [];

        /**
         * @type {TxtNode}
         */
        this.endIndex = endIndex;
    }

    getIgnoringMessages() {
        return this.reportingConfig.map(reporting => {
            if (reporting.endIndex === null) {
                // [start, ?= document-end]
                // filled with document's end
                reporting.endIndex = this.endIndex;
            }
            return reporting;
        });
    }

    /**
     * Add data to reporting configuration to disable reporting for list of rules
     * starting from start location
     * @param  {Object} startNode Node to start
     * @param  {string[]} rulesToDisable List of rules
     * @returns {void}
     */
    disableReporting(startNode, rulesToDisable) {
        const reportingConfig = this.reportingConfig;
        if (rulesToDisable.length) {
            rulesToDisable.forEach(function (ruleId) {
                reportingConfig.push({
                    startIndex: startNode.range[0],
                    endIndex: null,
                    ruleId: ruleId
                });
            });
        } else {
            reportingConfig.push({
                startIndex: startNode.range[0],
                endIndex: null,
                ruleId: null
            });
        }
    }

    /**
     * Add data to reporting configuration to enable reporting for list of rules
     * starting from start location
     * @param  {Object} startNode Node to start
     * @param  {string[]} rulesToEnable List of rules
     * @returns {void}
     */
    enableReporting(startNode, rulesToEnable) {
        var i;
        const endIndex = startNode.range[0];
        const reportingConfig = this.reportingConfig;
        if (rulesToEnable.length) {
            rulesToEnable.forEach(function (ruleId) {
                for (i = reportingConfig.length - 1; i >= 0; i--) {
                    if (!reportingConfig[i].endIndex && reportingConfig[i].ruleId === ruleId) {
                        reportingConfig[i].endIndex = endIndex;
                        break;
                    }
                }
            });
        } else {

            // find all previous disabled locations if they was started as list of rules
            var prevStart;

            for (i = reportingConfig.length - 1; i >= 0; i--) {
                if (prevStart && prevStart !== reportingConfig[i].start) {
                    break;
                }

                if (!reportingConfig[i].endIndex) {
                    reportingConfig[i].endIndex = endIndex;
                    prevStart = reportingConfig[i].start;
                }
            }
        }
    }

}