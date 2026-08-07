import uniq from "lodash.uniq";
import uniqWith from "lodash.uniqwith";
import sortBy from "lodash.sortby";
import escapeStringRegexp from "escape-string-regexp";
import { isRegExpString, parseRegExpString } from "./regexp-parse";

import execall from "execall";
import toRegex from "to-regex";

const DEFAULT_FLAGS = "g";

const defaultFlags = (flagsString: string) => {
    if (flagsString.length === 0) {
        return DEFAULT_FLAGS;
    }
    return uniq((flagsString + DEFAULT_FLAGS).split("")).join("");
};

export interface matchPatternResult {
    match: string;
    startIndex: number;
    endIndex: number;
}

export const createRegExp = (patternString: string, defaultFlag: string = DEFAULT_FLAGS): RegExp => {
    if (patternString.length === 0) {
        throw new Error("Empty string can not handled");
    }
    if (isRegExpString(patternString)) {
        const regExpStructure = parseRegExpString(patternString);
        if (regExpStructure) {
            return toRegex(regExpStructure.source, {
                flags: defaultFlags(regExpStructure.flagString),
                contains: true
            });
        }
        throw new Error(`"${patternString}" can not parse as RegExp.`);
    } else {
        return new RegExp(escapeStringRegexp(patternString), defaultFlag);
    }
};

const isEqualMatchPatternResult = (a: matchPatternResult, b: matchPatternResult): boolean => {
    return a.startIndex === b.startIndex && a.endIndex === b.endIndex && a.match === b.match;
};
/**
 * Match regExpLikeStrings and return matchPatternResults
 * @param text target text
 * @param regExpLikeStrings an array of pattern string
 */
export const matchPatterns = (text: string, regExpLikeStrings: string[]): matchPatternResult[] => {
    const matchPatternResults: matchPatternResult[] = [];
    regExpLikeStrings
        .map((patternString) => {
            return createRegExp(patternString);
        })
        .forEach((regExp) => {
            const execallResults = execall(regExp, text);
            execallResults.forEach((result) => {
                const match = result.match;
                const index = result.index;
                matchPatternResults.push({
                    match: match,
                    startIndex: index,
                    endIndex: index + match.length
                });
            });
        });
    const uniqResults = uniqWith(matchPatternResults, isEqualMatchPatternResult);
    return sortBy(uniqResults, ["startIndex", "endIndex"]);
};
