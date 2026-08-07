# textlint-filter-rule-whitelist

[textlint](https://github.com/textlint) [filter rule](https://github.com/textlint/textlint/blob/master/docs/filter-rule.md "Filter rule") that filter any word by white list.

## Install

Install with [npm](https://www.npmjs.com/):

    npm install textlint-filter-rule-whitelist

## Usage

Via `.textlintrc`(Recommended)

```json
{
    "filters": {
        "whitelist": {
            "allow": [
                "ignored-word",
                "/\\d{4}-\\d{2}-\\d{2}/",
                "/===IGNORE===[\\s\\S]*?===\/IGNORE===/m"
            ]
        }
    }
}
```

## Options

- `allow`: `string[]`
    - white list String or [RegExp-like String](https://github.com/textlint/regexp-string-matcher#regexp-like-string)
- `whitelistConfigPaths`: `string[]`
    - File path list that includes allow words.
    - The File path is relative path from your `.textlintrc`.
    - Support file format: JSON, yml, js

For example, you can specify `whitelistConfigPaths` to `.textlintrc`.

```json
{
    "filters": {
        "whitelist": {
            "whitelistConfigPaths": [
                "./allow.json",
                "./allow.yml"
            ]
        }
    }
}
```

These files should be following formats.

`allow.json`:
```
[
  "ignore-word",
  "/yes/i"
]
```

`allow.yml`:
```
- "ignore-word",
- /yes/i
```


## RegExp-like String

This filter rule support [RegExp-like String](https://github.com/textlint/regexp-string-matcher#regexp-like-string).
RegExp-like String is that started with `/` and ended with `/` or `/flag`.

:warning: Yous should escape special characters like `\d` in string literal.
`/\d/` should be `"\\d"`.

For example, you want to ignore `/\d{4}-\d{2}-\d{2}/` pattern, you can write `allow` as follows:

```js
[
  "/\\d{4}-\\d{2}-\\d{2}/"
]
```

### Example: Ignore pattern

Some textlint rule has false-positive about unique noun.
You want to ignore the error about unique noun.

For example, you want to ignore error about `/github/i`, you can write `allow` as follows:

`allow.json`:
```
[
  "/github/i`
]
```

### Example: Ignore range

You want to ignore error between `===IGNORE===` mark.

`allow.json`:
```
[
  "/===IGNORE===[\\s\\S]*?===/IGNORE===/m`
]
```

**text:**
```
ERROR Text => actual error

===IGNORE===
ERROR Text => it is ignored!
===/IGNORE===

ERROR Text => actual error
```

For more information, see [textlint/regexp-string-matcher – Example](https://github.com/textlint/regexp-string-matcher#examples)

## Changelog

See [Releases page](https://github.com/textlint/textlint-filter-rule-whitelist/releases).

## Running tests

Install devDependencies and Run `npm test`:

    npm i -d && npm test

## Contributing

Pull requests and stars are always welcome.

For bugs and feature requests, [please create an issue](https://github.com/textlint/textlint-filter-rule-whitelist/issues).

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
