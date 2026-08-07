# @textlint/regexp-string-matcher [![Actions Status: test](https://github.com/textlint/regexp-string-matcher/workflows/test/badge.svg)](https://github.com/textlint/regexp-string-matcher/actions?query=workflow%3A"test")

Regexp-like string matcher library.

## Install

Install with [npm](https://www.npmjs.com/):

    npm install @textlint/regexp-string-matcher

## Usage

Interface:

```ts
export interface matchPatternResult {
    match: string;
    startIndex: number;
    endIndex: number;
}
/**
 * Match regExpLikeStrings and return matchPatternResults
 * @param text target text
 * @param regExpLikeStrings an array of pattern string
 */
export declare const matchPatterns: (text: string, regExpLikeStrings: string[]) => matchPatternResult[];
```

Example:

```js
import { matchPatterns } from "@textlint/regexp-string-matcher";
const inputText = `
GitHub is a web-based hosting service for version control using git.
It is mostly used for computer code.
GitHub launched in 2018-04-10.`;
// RegExp like strings
const inputPatterns = [
    "git", // => /git/g
    "/github/i", // => /github/ig
    "/\\d{4}-\\d{2}-\\d{2}/" // => /\d{4}-\d{2}-\d{2}/g
];

const results = matchPatterns(inputText, inputPatterns);
assert.deepStrictEqual(results, [
    { match: "GitHub", startIndex: 1, endIndex: 7 },
    { match: "git", startIndex: 65, endIndex: 68 },
    { match: "GitHub", startIndex: 107, endIndex: 113 },
    { match: "2018-04-10", startIndex: 126, endIndex: 136 }
]);
```

## RegExp-like String

This library aim to represent RegExp in JSON and use it for ignoring words.
`g`(global) flag is added by default, Because ignoring words is always global in a document.


| Input | Ouput | Note|
| ---- | ---| --- |
| `"str"` | `/str/g`| convert string to regexp with global |
| `"/str/"` | `/str/g`| |
| `"/str/g"` | `/str/g`| Duplicated `g` is just ignored |
| `"/str/i"` | `/str/ig`| |
| `"/str/u"` | `/str/ug`| |
| `"/str/m"` | `/str/mg`| |
| `"/str/y"` | `/str/yg`| |
| ---|---| --- |
| `"/\\d+/"` | `/\d+/g`| You should escape meta character like `\d` |

:warning: You should escape meta character like `\d` in RegExp-like string.

For example, If you want to write `\w`(any word) in RegExp-like string, you should escape `\w` to `\\w`.

- [Regular Expressions - JavaScript | MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions#Using_special_characters)

Text:

```
This is a pen.
```

RegExp-like String:

```json
[
    "/a \\w+/"
]
```

Results:

```
[ { match: 'a pen', startIndex: 8, endIndex: 13 } ]
```

## Examples

### string

**text:**
```markdown
GitHub is a web-based hosting service for version control using git.
It is mostly used for computer code.
GitHub launched in 2018-04-10.
```

**pattern:**

```json
[
  "GitHub"
]
```

**results:** 2 hits
```markdown
**GitHub** is a web-based hosting service for version control using git.
It is mostly used for computer code.
**GitHub** launched in 2018-04-10.
```

### Ignore Case match

**text:**
```markdown
GitHub is a web-based hosting service for version control using git.
It is mostly used for computer code.
GitHub launched in 2018-04-10.
```

**pattern:**

```json
[
  "/git/i"
]
```

**results:**: 3 hits
```markdown
**Git**Hub is a web-based hosting service for version control using **git**.
It is mostly used for computer code.
**Git**Hub launched in 2018-04-10.
```

### Special character

You should escape special charactor like `\d` in RegExp-like string.

**text:**
```markdown
GitHub is a web-based hosting service for version control using git.
It is mostly used for computer code.
GitHub launched in 2018-04-10.
```

**pattern:**
```json
[
  "/\\d{4}-\\d{2}-\\d{2}/"
]
```

**results:**: 1 hit
```markdown
GitHub is a web-based hosting service for version control using git.
It is mostly used for computer code.
GitHub launched in **2018-04-10**.
```

### Multi-line


**text:**
```markdown
===START===
1st inline text.
===END===

===START===
2nd inline text.
===END===
```

**pattern:**
```json
[
  "/===START===[\\s\\S]*?===END===/m"
]

```

**results:**: 2 hits
```markdown
**===START===
1st inline text.
===END===**

**===START===
2nd inline text.
===END===**
```


For more details, see [test/snapshots](./test/snapshots)

## Changelog

See [Releases page](https://github.com/textlint/regexp-string-matcher/releases).

## Running tests

Install devDependencies and Run `npm test`:

    npm i -d && npm test

### How to add snapshot tests?

1. Create new dir to `./snapshots/<name>/`
2. Add `input.txt` and `input-patterns.json`
3. Run `npm run test:updateSnapshot`
4. You should verify the output results manually
5. Run `npm test` and pass it
5. Commit it

## Contributing

Pull requests and stars are always welcome.

For bugs and feature requests, [please create an issue](https://github.com/textlint/regexp-string-matcher/issues).

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## Author

- [github/azu](https://github.com/azu)
- [twitter/azu_re](https://twitter.com/azu_re)

## License

MIT © azu
