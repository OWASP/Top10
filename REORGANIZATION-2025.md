# OWASP Top 10 Multi-Version Reorganization

## Summary

This document records the reorganization performed to properly separate the 2021 and 2025 versions of the OWASP Top 10 documentation into independent MkDocs sites while maintaining backward compatibility with existing URLs.

## Why This Was Needed

### The Problem

When the 2025 Release Candidate was being developed, the 2025 content was temporarily placed in `/2021/docs/en/2025/` and the `/2021/mkdocs.yml` file was modified to include both 2021 and 2025 content in a single combined site. This created several issues:

1. **Confusing structure** - The "2021" directory contained both 2021 and 2025 content
2. **Difficult maintenance** - One mkdocs.yml file controlled both versions
3. **Unclear ownership** - It wasn't clear which version was "primary"
4. **Messy navigation** - The site showed both "Current Release" and "Release Candidate" sections
5. **Improper location** - 2025 files belonged in `/2025/docs/en/`, not in the 2021 directory

### The Solution

Reorganize the repository to:
- Move 2025 docs to their proper location (`/2025/docs/en/`)
- Create separate, independent MkDocs configurations for each version
- Build both sites separately and deploy them together
- Maintain backward compatibility with existing 2021 URLs using HTML redirects

## Files Moved (with git history preserved)

### Markdown Files
All moved from `/2021/docs/en/2025/` to `/2025/docs/en/`:
- `0x00_2025-Introduction.md`
- `0x01_2025-About_OWASP.md`
- `0x02_2025-What_are_Application_Security_Risks.md`
- `0x03_2025-Establishing_a_Modern_Application_Security_Program.md`
- `A01_2025-Broken_Access_Control.md`
- `A02_2025-Security_Misconfiguration.md`
- `A03_2025-Software_Supply_Chain_Failures.md`
- `A04_2025-Cryptographic_Failures.md`
- `A05_2025-Injection.md`
- `A06_2025-Insecure_Design.md`
- `A07_2025-Authentication_Failures.md`
- `A08_2025-Software_or_Data_Integrity_Failures.md`
- `A09_2025-Logging_and_Alerting_Failures.md`
- `A10_2025-Mishandling_of_Exceptional_Conditions.md`
- `X01_2025-Next_Steps.md`

### Assets
- **Images**: `2025-algorithm-diagram.png`, `2025-mappings.png` moved from `/2021/docs/assets/` to `/2025/docs/assets/`
- **CSS**: `RC-stylesheet.css` moved from `/2021/docs/assets/css/` to `/2025/docs/assets/css/`
- **Shared assets copied**: `OWASP_Logo_Transp.png`, `TOP_10_logo_Final_Logo_Colour.png` copied to `/2025/docs/assets/`

## Files Created

### Documentation
- `/2025/docs/en/index.md` - Welcome page for 2025 version
- `/REORGANIZATION-2025.md` - This file

### Build Scripts
- `/scripts/build-all.sh` - Orchestrates building both 2021 and 2025 sites
- `/scripts/generate-redirects.sh` - Creates HTML redirect pages for backward compatibility
- `/scripts/index-redirect.html` - Root redirect template (redirects `/` to `/2021/en/`)

## Files Modified

### MkDocs Configurations
- **/2021/mkdocs.yml**
  - Changed `site_name` from "OWASP Top 10:2025 RC1" back to "OWASP Top 10:2021"
  - Changed `site_description` to "OWASP Top 10:2021"
  - Added `site_url: https://owasp.org/Top10/2021/`
  - Removed entire "Release Candidate" navigation section
  - Simplified navigation to only include 2021 content

- **/2025/mkdocs.yml**
  - Added `site_url: https://owasp.org/Top10/2025/`
  - Updated all navigation paths from `'2025/...'` to `'en/...'`
  - Added `- Home: 'en/index.md'` to navigation
  - Changed repo_url from development URL to production

### Build System
- **/Makefile**
  - Added `build-2021` target - builds only 2021 site
  - Added `build-2025` target - builds only 2025 site
  - Added `build-all` target - builds both sites with redirects
  - Added `serve-2021` target - serves 2021 site on port 8000
  - Added `serve-2025` target - serves 2025 site on port 8001
  - Updated `publish` target - now deploys both sites together
  - Kept `generate` and `serve` for backward compatibility

## Directory Structure Changes

### Before
```
/2021/
├── docs/
│   ├── en/
│   │   ├── A01_2021-*.md           # 2021 content
│   │   ├── 2025/                    # ← 2025 content wrongly here
│   │   │   ├── 0x00_2025-*.md
│   │   │   └── A01_2025-*.md
│   │   └── index.md
│   └── assets/
│       ├── 2025-*.png               # ← 2025 assets wrongly here
│       └── css/RC-stylesheet.css    # ← 2025 CSS wrongly here
└── mkdocs.yml                       # Combined 2021+2025 config

/2025/
├── docs/
│   ├── README.md
│   └── assets/
└── mkdocs.yml                       # Pointed to wrong paths
```

### After
```
/2021/
├── docs/
│   ├── en/
│   │   ├── A01_2021-*.md           # 2021 content only
│   │   └── index.md
│   └── assets/                      # 2021 assets only
└── mkdocs.yml                       # 2021-only config

/2025/
├── docs/
│   ├── en/
│   │   ├── 0x00_2025-*.md          # 2025 content
│   │   ├── A01_2025-*.md
│   │   └── index.md
│   └── assets/
│       ├── 2025-*.png               # 2025 assets
│       └── css/RC-stylesheet.css    # 2025 CSS
└── mkdocs.yml                       # 2025-only config

/scripts/
├── build-all.sh                     # Build orchestration
├── generate-redirects.sh            # Redirect generation
└── index-redirect.html              # Root redirect template
```

## URL Structure

### Production URLs
- `https://owasp.org/Top10/` → Redirects to 2021 (preserves existing links)
- `https://owasp.org/Top10/2021/` → 2021 site
- `https://owasp.org/Top10/2025/` → 2025 site

### Backward Compatibility

The build system automatically generates HTML redirect pages to ensure old URLs continue to work:

**Root-level page redirects:**
- `/A00_2021_Introduction/` → `/Top10/2021/A00_2021_Introduction/`
- `/A01_2021-Broken_Access_Control/` → `/Top10/2021/A01_2021-Broken_Access_Control/`
- All 2021 pages that were previously at the root now redirect to `/Top10/2021/`

**Language directory redirects:**
- `/en/` → `/Top10/2021/` (English is at root of 2021)
- `/ar/` → `/Top10/2021/ar/`
- `/de/` → `/Top10/2021/de/`
- `/es/` → `/Top10/2021/es/`
- All 11 languages supported

**Version-specific `/en/` redirects:**
- `/2021/en/` → `/Top10/2021/` (English moved from subdirectory to root)
- `/2021/en/A00_2021_Introduction/` → `/Top10/2021/A00_2021_Introduction/`
- `/2025/en/` → `/Top10/2025/` (English at root for 2025 too)
- `/2025/en/A01_2025-Broken_Access_Control/` → `/Top10/2025/A01_2025-Broken_Access_Control/`

All redirects are created by `scripts/generate-redirects.sh` during the build process and use absolute paths with `/Top10/` prefix to work correctly when deployed to `owasp.org/Top10/`.

**Language Selector Fix:**
The `extra.alternate` section was removed from `2021/mkdocs.yml` to allow the i18n plugin with `material_alternate: true` to automatically generate correct language selector links based on the `site_url` configuration. This ensures language links work correctly both locally and in production.

## Build Process

### Building and Serving

```bash
# Build only 2021
make build-2021

# Build only 2025
make build-2025

# Build and serve both versions together (port 8000)
make serve

# Serve individual versions with live-reload
make serve-2021  # Port 8000
make serve-2025  # Port 8001
```

The `make serve` command builds both sites and serves them together using Python's HTTP server:
- http://localhost:8000/2021/ - 2021 version
- http://localhost:8000/2025/ - 2025 version

The individual `serve-2021` and `serve-2025` targets use MkDocs' live-reload feature for rapid development.

### Building Both Versions
```bash
# Build both sites with redirects
make build-all

# Or use the script directly
./scripts/build-all.sh
```

This creates:
- `build/2021/` - Complete 2021 site
- `build/2025/` - Complete 2025 site
- `build/index.html` - Root redirect to 2021
- `build/en/`, `build/ar/`, etc. - HTML redirects for backward compatibility

### Deployment
```bash
# Deploy both sites to GitHub Pages
make publish
```

This:
1. Runs `build-all` to build both sites
2. Creates a git repository in the `build/` directory
3. Force-pushes to the `gh-pages` branch

## Testing Checklist

After reorganization, verify:

- [ ] `make serve-2021` starts 2021 site successfully
- [ ] `make serve-2025` starts 2025 site successfully
- [ ] 2021 site shows only 2021 content (no 2025 references)
- [ ] 2025 site shows only 2025 content with RC watermark
- [ ] All images load correctly in both versions
- [ ] All 11 languages work in 2021 site
- [ ] `make build-all` completes without errors
- [ ] Generated redirects exist for all languages
- [ ] Root `index.html` redirects to 2021
- [ ] After deployment, all three URLs work:
  - `https://owasp.org/Top10/` (root)
  - `https://owasp.org/Top10/2021/`
  - `https://owasp.org/Top10/2025/`
- [ ] Old 2021 URLs redirect properly
- [ ] No 404 errors on previously working links

## Troubleshooting

### Issue: mkdocs build fails for 2025
**Cause**: Navigation references files that don't exist
**Solution**: Check that all paths in `/2025/mkdocs.yml` start with `'en/...'` and files exist in `/2025/docs/en/`

### Issue: Images don't load in 2025 site
**Cause**: Asset paths still reference `../../assets/`
**Solution**: Paths should be `../assets/` in all 2025 markdown files

### Issue: Redirects don't work
**Cause**: `generate-redirects.sh` not executed or build directory missing
**Solution**: Run `./scripts/build-all.sh` which calls the redirect script

### Issue: `make publish` fails
**Cause**: Git authentication or build errors
**Solution**: Ensure SSH keys are configured for GitHub and build completes successfully

### Issue: Old 2021 URLs return 404
**Cause**: HTML redirects weren't generated or deployed
**Solution**: Verify `build/en/`, `build/ar/`, etc. directories contain `index.html` redirect files

## Future Maintenance

### Adding a New Version (e.g., 2028)
1. Create `/2028/` directory with same structure as 2025
2. Create `/2028/mkdocs.yml` with `site_url: https://owasp.org/Top10/2028/`
3. Add `build-2028` target to Makefile
4. Update `/scripts/build-all.sh` to include 2028 build
5. Update root redirect if needed (when 2028 becomes official release)

### Adding Translations to 2025
1. Copy language directory from 2021 (e.g., `/2021/docs/fr/` → `/2025/docs/fr/`)
2. Translate markdown files
3. Update `/2025/mkdocs.yml` to add language to i18n plugin configuration
4. Add nav_translations for the new language

### Updating from RC to Final Release
1. Remove `RC-stylesheet.css` reference from `/2025/mkdocs.yml`
2. Update `/scripts/index-redirect.html` to redirect to 2025 instead of 2021
3. Rebuild and redeploy

## Impact Summary

- **Git history preserved**: All 2025 files moved with `git mv` to maintain history
- **Backward compatibility maintained**: Existing 2021 URLs continue to work via redirects
- **Clean separation**: Each version has its own independent configuration and build
- **Flexible deployment**: Can build/serve versions independently or together
- **Scalable**: Pattern established for future versions (2028, 2031, etc.)
- **Standard tools**: Uses `mkdocs serve` and `mkdocs build` - no custom tooling required

## Related Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) - Build process for maintainers
- [Plan file](/Users/neil/.claude/plans/luminous-noodling-candle.md) - Original implementation plan
