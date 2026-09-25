export interface rcConfigLoaderOption {
    // does look for `package.json`
    packageJSON?:
        | boolean
        | {
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
