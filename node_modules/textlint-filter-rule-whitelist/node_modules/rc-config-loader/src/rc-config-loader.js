// MIT © 2017 azu
// MIT © Zoltan Kochan
// Original https://github.com/zkochan/rcfile
"use strict";
const path = require("path");
const debug = require("debug")("rc-config-loader");
const requireFromString = require("require-from-string");
const JSON5 = require("json5");
const fs = require("fs");
const pathExists = require("path-exists");
const objectAssign = require("object-assign");
const keys = require("object-keys");

const defaultLoaderByExt = {
    ".js": loadJSConfigFile,
    ".json": loadJSONConfigFile,
    ".yaml": loadYAMLConfigFile,
    ".yml": loadYAMLConfigFile
};

const defaultOptions = {
    // does look for `package.json`
    packageJSON: false,
    // treat default(no ext file) as some extension
    defaultExtension: [".json", ".yaml", ".yml", ".js"],
    cwd: process.cwd()
};

/**
 * @param {string} pkgName
 * @param {rcConfigLoaderOption} [opts]
 * @returns {{ config: Object, filePath:string } | undefined}
 */
module.exports = function rcConfigLoader(pkgName, opts = {}) {
    // path/to/config or basename of config file.
    const configFileName = opts.configFileName || `.${pkgName}rc`;
    const defaultExtension = opts.defaultExtension || defaultOptions.defaultExtension;
    const cwd = opts.cwd || defaultOptions.cwd;
    const packageJSON = opts.packageJSON || defaultOptions.packageJSON;
    const packageJSONFieldName = typeof packageJSON === "object" ? packageJSON.fieldName : pkgName;

    const parts = splitPath(cwd);

    const loaders = Array.isArray(defaultExtension)
        ? defaultExtension.map(extension => defaultLoaderByExt[extension])
        : defaultLoaderByExt[defaultExtension];

    const loaderByExt = objectAssign({}, defaultLoaderByExt, {
        "": loaders
    });

    return findConfig({ parts, loaderByExt, configFileName, packageJSON, packageJSONFieldName });
};

/**
 *
 * @param {string[]} parts
 * @param {Object} loaderByExt
 * @param {string} configFileName
 * @param {boolean|Object} packageJSON
 * @param {string} packageJSONFieldName
 * @returns {{
 *  config: string,
 *  filePath: string
 * }|undefined}
 */
function findConfig({ parts, loaderByExt, configFileName, packageJSON, packageJSONFieldName }) {
    const exts = keys(loaderByExt);
    while (exts.length) {
        const ext = exts.shift();
        const configLocation = join(parts, configFileName + ext);
        if (!pathExists.sync(configLocation)) {
            continue;
        }
        const loaders = loaderByExt[ext];
        if (!Array.isArray(loaders)) {
            const loader = loaders;
            const result = loader(configLocation);
            if (!result) {
                continue;
            }
            return {
                config: result,
                filePath: configLocation
            };
        }
        for (let i = 0; i < loaders.length; i++) {
            const loader = loaders[i];
            const result = loader(configLocation, true);
            if (!result) {
                continue;
            }
            return {
                config: result,
                filePath: configLocation
            };
        }
    }

    if (packageJSON) {
        const pkgJSONLoc = join(parts, "package.json");
        if (pathExists.sync(pkgJSONLoc)) {
            const pkgJSON = require(pkgJSONLoc);
            if (pkgJSON[packageJSONFieldName]) {
                return {
                    config: pkgJSON[packageJSONFieldName],
                    filePath: pkgJSONLoc
                };
            }
        }
    }
    if (parts.pop()) {
        return findConfig({ parts, loaderByExt, configFileName, packageJSON, packageJSONFieldName });
    }
    return undefined;
}

function splitPath(x) {
    return path.resolve(x || "").split(path.sep);
}

function join(parts, filename) {
    return path.resolve(parts.join(path.sep) + path.sep, filename);
}

function loadJSConfigFile(filePath, suppress) {
    debug(`Loading JavaScript config file: ${filePath}`);
    try {
        const content = fs.readFileSync(filePath, "utf-8");
        return requireFromString(content, filePath);
    } catch (e) {
        debug(`Error reading JavaScript file: ${filePath}`);
        if (!suppress) {
            e.message = `Cannot read config file: ${filePath}\nError: ${e.message}`;
            throw e;
        }
    }
}

function loadJSONConfigFile(filePath, suppress) {
    debug(`Loading JSON config file: ${filePath}`);

    try {
        return JSON5.parse(readFile(filePath));
    } catch (e) {
        debug(`Error reading JSON file: ${filePath}`);
        if (!suppress) {
            e.message = `Cannot read config file: ${filePath}\nError: ${e.message}`;
            throw e;
        }
    }
}

function readFile(filePath) {
    return fs.readFileSync(filePath, "utf8");
}

function loadYAMLConfigFile(filePath, suppress) {
    debug(`Loading YAML config file: ${filePath}`);

    // lazy load YAML to improve performance when not used
    const yaml = require("js-yaml");

    try {
        // empty YAML file can be null, so always use
        return yaml.safeLoad(readFile(filePath)) || {};
    } catch (e) {
        debug(`Error reading YAML file: ${filePath}`);
        if (!suppress) {
            e.message = `Cannot read config file: ${filePath}\nError: ${e.message}`;
            throw e;
        }
    }
}
