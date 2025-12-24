# Contributing

We encourage anyone to contribute issues, feedback and so on via logging an issue. Once the OWASP Top 10 has been released, it might be a while before that feedback is incorporated into the next version (up to 3 years).

## Translations

If you are interested in translating the OWASP Top 10, please contact @owasptop10 on Twitter - someone else might already be working on your language, and you can help that effort instead of doing it over. Generally, we will create a project for you, or you can fork the main repo and provide us a pull request once you're done. To maintain traceability, we do ask that you translate the markdown as well, as that's what is included in the Wiki version.

## Forking

You are more than welcome to fork the OWASP Top 10, but please abide by the Creative Commons BY-SA 4.0 license.

## Pull requests

We welcome pull requests for fixes, but again, it might be a while before we accept any changes to the final version of the OWASP Top 10.

## Building

The OWASP Top 10 repository contains multiple versions (2021, 2025, etc.). Each version is an independent MkDocs site that can be built separately or together.

### Quick Start

Run `make help` to see all available make targets.

**First time setup:**
```bash
make install-python-requirements
```

**Build both versions:**
```bash
make all          # Install dependencies and build both sites
make build-all    # Just build both sites
```

**Serve both versions together:**
```bash
make serve        # Builds and serves both versions on port 8000
```

Visit the site at:
- http://localhost:8000/2021/ - 2021 version
- http://localhost:8000/2025/ - 2025 version

**Serve a specific version (with live-reload):**
```bash
make serve-2021   # Serve 2021 version on port 8000
make serve-2025   # Serve 2025 version on port 8001
```

These targets use MkDocs' live-reload feature for rapid development on a single version.

### Building for Production

**Build individual versions:**
```bash
make build-2021  # Builds to build/2021/
make build-2025  # Builds to build/2025/
```

**Build both versions together:**
```bash
make build-all
```

This creates a combined build with:
- `build/2021/` - Complete 2021 site
- `build/2025/` - Complete 2025 site
- `build/index.html` - Root redirect to 2021
- `build/en/`, `build/ar/`, etc. - HTML redirects for backward compatibility

### Deployment

**Deploy to GitHub Pages:**
```bash
make publish
```

This builds both versions and deploys them together to the `gh-pages` branch.

### Directory Structure

```
/2021/
├── docs/
│   ├── en/              # English content
│   ├── ar/              # Arabic content
│   ├── de/              # German content
│   └── ...              # Other languages
└── mkdocs.yml           # 2021 configuration

/2025/
├── docs/
│   └── en/              # English only (for now)
└── mkdocs.yml           # 2025 configuration

/scripts/
├── build-all.sh         # Orchestrates multi-version builds
├── generate-redirects.sh # Creates backward-compatible redirects
└── index-redirect.html  # Root redirect template
```

### Adding a New Version

When it's time to create a new version (e.g., 2028):

1. **Create directory structure:**
   ```bash
   mkdir -p 2028/docs/en/
   ```

2. **Create mkdocs.yml** based on 2025 version:
   ```yaml
   site_name: OWASP Top 10:2028
   site_url: https://owasp.org/Top10/2028/
   # ... rest of configuration
   ```

3. **Update Makefile** - add build-2028 and serve-2028 targets

4. **Update build-all.sh** to include the new version

5. **Update redirects** when the new version becomes official

6. **Update www-project-top-ten project**  when the new version becomes official ([repo](https://github.com/OWASP/www-project-top-ten))

7. **Update scripts/index-redirect.html** to point to the new version

### For Translators

Translations are added post-release as they become available.

To add a translation:

1. Copy the English directory:
   ```bash
   cp -r 2025/docs/en/ 2025/docs/fr/  # French example
   ```

2. Translate all markdown files

3. Update `2025/mkdocs.yml` to include the new language in the i18n plugin configuration

4. Test locally:
   ```bash
   make serve-2025
   ```

See the 2021 mkdocs.yml for examples of complete i18n configurations with nav_translations.

### Backward Compatibility

The build system automatically generates HTML redirect pages to ensure old 2021 URLs continue to work:
- `/en/A01_2021_Introduction/` → `/2021/en/A01_2021_Introduction/`
- All language paths are preserved

These redirects are created by `scripts/generate-redirects.sh` during the build process.

### Troubleshooting

**Build fails:**
- Check that Python virtual environment is activated
- Verify all required packages are installed: `make install-python-requirements`
- Check mkdocs.yml navigation paths match actual file locations

**Images don't load:**
- Verify asset paths in markdown files are correct (`../assets/` for most files)
- Check that image files exist in the assets directory

**Serve port already in use:**
- Change the port: `make serve-2021 port=8080`
- Or stop the process using the port

For more details, see [REORGANIZATION-2025.md](REORGANIZATION-2025.md).
