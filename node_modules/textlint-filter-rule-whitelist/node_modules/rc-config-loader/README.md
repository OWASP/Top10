# rc-config-loader [![Build Status](https://travis-ci.org/azu/rc-config-loader.svg?branch=master)](https://travis-ci.org/azu/rc-config-loader)

Load config from `.{product}rc.{json,yml,js}` file.

It is a Node.js library for loading `.textlintrc`, `.eslintrc`, `.stylelintrc` etc...

## Features

Find and load a configuration object from:

- a `package.json` property if it is needed
- a JSON or YAML, JS "rc file"
    - `.<product>rc` or `.<product>rc.json` or `.<product>rc.js` or`.<product>rc.yml`, `.<product>rc.yaml`
- TypeScript support
    - Includes `.d.ts`

## Difference

### with [MoOx/rc-loader](https://github.com/MoOx/rc-loader "MoOx/rc-loader")

- Safe API
    - `rc` contains shabang in `.js` file
- Enhance Error message

### with [cosmiconfig](https://github.com/davidtheclark/cosmiconfig "cosmiconfig")

- <del>Sync loading</del>
    - [cosmiconfig@3+](https://github.com/davidtheclark/cosmiconfig/blob/master/CHANGELOG.md#300) support `sync` option

## Install

Install with [npm](https://www.npmjs.com/):

    npm install rc-config-loader

## Usage

### API

```ts
export interface rcConfigLoaderOption {
    // does look for `package.json`
    packageJSON?: boolean | {
        fieldName: string;
    };
    // if config file name is not same with packageName, set the name
    configFileName?: string;
    // treat default(no ext file) as some extension
    defaultExtension?: string | string[];
    // where start to load
    cwd?: string;
}
export default function rcConfigLoader(packageName: string, options?: rcConfigLoaderOption): Object;
```

`rcConfigLoader` return `{ config, filePath }` object.

- `config`: it is config object
- `filePath`: absolute path to config file

If not found config file, return `undefined`.

### Example

```js
"use strict";
const rcfile = require("rc-config-loader");
// load .eslintrc from current dir
console.log(rcfile("eslint"));

// load .eslintrc from specific path
console.log(rcfile("eslint", {
    configFileName: `${__dirname}/test/fixtures/.eslintrc`
}));
/*
config: { extends: 'standard',
  rules:
   { 'comma-dangle': [ 2, 'always-multiline' ],
     'arrow-parens': [ 2, 'as-needed' ] } }
filePath: ${__dirname}/test/fixtures/.eslintrc
 */

// load property from pacakge.json
console.log(rcfile("rc-config-loader", {
    packageJSON: {
        fieldName: "directories"
    }
}));
/*
config: { test: 'test' }
filePath: /path/to/package.json
 */

// load .eslintrc from specific dir
console.log(rcfile("eslint", {
    cwd: `${__dirname}/test/fixtures`
}));

// load specific filename from current dir
console.log(rcfile("travis", {configFileName: ".travis"}));
/*
config: { sudo: false, language: 'node_js', node_js: 'stable' }
filePath: /path/to/.travis
 */

// try to load as .json, .yml, js
console.log(rcfile("bar", {
    configFileName: `${__dirname}/test/fixtures/.barrc`,
    defaultExtension: [".json", ".yml", ".js"]
}));

// try to load as .json, but it is not json
// throw Error
try {
    rcfile("unknown", {
        // This is not json
        configFileName: `${__dirname}/test/fixtures/.unknownrc`,
        defaultExtension: ".json"
    })
} catch (error) {
    console.log(error);
    /*
    SyntaxError: Cannot read config file: /test/fixtures/.unknownrc
    */
}

```

## Users

- [textlint](https://github.com/textlint/textlint "textlint")

## Changelog

See [Releases page](https://github.com/azu/rc-config-loader/releases).

## Running tests

Install devDependencies and Run `npm test`:

    npm i -d && npm test

## Contributing

Pull requests and stars are always welcome.

For bugs and feature requests, [please create an issue](https://github.com/azu/rc-config-loader/issues).

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

## Acknowledgement

- [zkochan/rcfile: Loads library configuration in all possible ways](https://github.com/zkochan/rcfile "zkochan/rcfile: Loads library configuration in all possible ways")

**Difference**

- support multiple `defaultExtension`  
