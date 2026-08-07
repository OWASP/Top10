const REGEXP_LITERAL_PATTERN = /^\/(.*)\/([guimy]*)$/;
export const parseRegExpString = (str: string): { source: string; flagString: string } | null => {
    const result = str.match(REGEXP_LITERAL_PATTERN);
    if (!result) {
        return null;
    }
    return {
        source: result[1],
        flagString: result[2]
    };
};
export const isRegExpString = (str: string): boolean => {
    return REGEXP_LITERAL_PATTERN.test(str);
};
