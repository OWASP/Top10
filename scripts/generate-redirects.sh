#!/bin/bash
# Generates HTML redirect pages for backward compatibility
# This ensures old URLs like /en/A01_2021_Introduction/ redirect to /2021/en/A01_2021_Introduction/

REDIRECT_DIR="build"
LANGUAGES=("en" "ar" "de" "es" "fr" "id" "it" "ja" "pt-BR" "tr" "zh-Hant" "zh-TW")

echo "Generating HTML redirects for backward compatibility..."

# First, create redirects for old root-level English pages
# These were at the root before the reorganization (e.g., /A00_2021_Introduction/)
# Now they need to redirect to /2021/A00_2021_Introduction/
echo "Creating redirects for root-level English pages..."
find "$REDIRECT_DIR/2021" -maxdepth 2 -name "*.html" -type f | while read file; do
    # Get relative path from 2021/
    rel_path="${file#$REDIRECT_DIR/2021/}"

    # Skip if it's in a language subdirectory or is index.html/404.html
    if [[ "$rel_path" =~ ^(ar|de|es|fr|id|it|ja|pt-BR|tr|zh-Hant|zh-TW)/ ]] || \
       [[ "$rel_path" == "index.html" ]] || [[ "$rel_path" == "404.html" ]]; then
        continue
    fi

    # Skip files that are inside subdirectories (only want direct files/dirs)
    if [[ "$rel_path" == */index.html ]]; then
        # This is a page directory, create redirect
        page_dir=$(dirname "$rel_path")

        # Create directory structure at root
        mkdir -p "$REDIRECT_DIR/$page_dir"

        # Create redirect HTML (use absolute path from /Top10/)
        cat > "$REDIRECT_DIR/$rel_path" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=/Top10/2021/$rel_path">
    <link rel="canonical" href="/Top10/2021/$rel_path">
</head>
<body>
    <p>Redirecting to <a href="/Top10/2021/$rel_path">OWASP Top 10:2021</a>...</p>
</body>
</html>
EOF
    fi
done

echo "Creating redirects for language directories..."

for lang in "${LANGUAGES[@]}"; do
    # Create redirect directory at root for each language
    mkdir -p "$REDIRECT_DIR/$lang"

    # English is at root of 2021, other languages are in subdirectories
    if [ "$lang" = "en" ]; then
        REDIRECT_TARGET="/Top10/2021/"
    else
        REDIRECT_TARGET="/Top10/2021/$lang/"
    fi

    # Create index.html redirect in each language directory
    cat > "$REDIRECT_DIR/$lang/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=$REDIRECT_TARGET">
    <link rel="canonical" href="$REDIRECT_TARGET">
</head>
<body>
    <p>Redirecting to <a href="$REDIRECT_TARGET">OWASP Top 10:2021 ($lang)</a>...</p>
</body>
</html>
EOF

    # For each page in the 2021 build, create a corresponding redirect
    # English pages are at /2021/ root, other languages are in /2021/$lang/
    if [ "$lang" = "en" ]; then
        # English: redirect /en/page.html to /2021/page.html
        find "$REDIRECT_DIR/2021" -maxdepth 2 -name "*.html" -type f | while read file; do
            # Get relative path from 2021/
            rel_path="${file#$REDIRECT_DIR/2021/}"

            # Skip if it's in a language subdirectory
            if [[ "$rel_path" =~ ^(ar|de|es|fr|id|it|ja|pt-BR|tr|zh-Hant|zh-TW)/ ]]; then
                continue
            fi

            # Create directory structure if needed
            dir_path=$(dirname "$REDIRECT_DIR/$lang/$rel_path")
            mkdir -p "$dir_path"

            # Create redirect HTML
            cat > "$REDIRECT_DIR/$lang/$rel_path" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=/Top10/2021/$rel_path">
    <link rel="canonical" href="/Top10/2021/$rel_path">
</head>
<body>
    <p>Redirecting to <a href="/Top10/2021/$rel_path">OWASP Top 10:2021</a>...</p>
</body>
</html>
EOF
        done
    elif [ -d "$REDIRECT_DIR/2021/$lang" ]; then
        # Other languages: redirect /lang/page.html to /2021/lang/page.html
        find "$REDIRECT_DIR/2021/$lang" -name "*.html" -type f | while read file; do
            # Get relative path from 2021/$lang/
            rel_path="${file#$REDIRECT_DIR/2021/$lang/}"

            # Create directory structure if needed
            dir_path=$(dirname "$REDIRECT_DIR/$lang/$rel_path")
            mkdir -p "$dir_path"

            # Create redirect HTML
            cat > "$REDIRECT_DIR/$lang/$rel_path" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=/Top10/2021/$lang/$rel_path">
    <link rel="canonical" href="/Top10/2021/$lang/$rel_path">
</head>
<body>
    <p>Redirecting to <a href="/Top10/2021/$lang/$rel_path">OWASP Top 10:2021</a>...</p>
</body>
</html>
EOF
        done
    fi
done

# Create redirects for old /2021/en/* URLs to /2021/* (English moved from subdirectory to root)
echo "Creating redirects for old /2021/en/ URLs..."
find "$REDIRECT_DIR/2021" -maxdepth 2 -type d | while read dir; do
    dirname=$(basename "$dir")

    # Skip the 2021 directory itself and language directories
    if [[ "$dirname" == "2021" ]] || [[ "$dirname" =~ ^(ar|de|es|fr|id|it|ja|pt-BR|tr|zh-Hant|zh-TW|assets|search)$ ]]; then
        continue
    fi

    # Create en subdirectory structure
    mkdir -p "$REDIRECT_DIR/2021/en/$dirname"

    # Create redirect for this page
    cat > "$REDIRECT_DIR/2021/en/$dirname/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=/Top10/2021/$dirname/">
    <link rel="canonical" href="/Top10/2021/$dirname/">
</head>
<body>
    <p>Redirecting to <a href="/Top10/2021/$dirname/">OWASP Top 10:2021</a>...</p>
</body>
</html>
EOF
done

# Create redirect for /2021/en/ index
if [ -f "$REDIRECT_DIR/2021/index.html" ]; then
    mkdir -p "$REDIRECT_DIR/2021/en"
    cat > "$REDIRECT_DIR/2021/en/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=/Top10/2021/">
    <link rel="canonical" href="/Top10/2021/">
</head>
<body>
    <p>Redirecting to <a href="/Top10/2021/">OWASP Top 10:2021</a>...</p>
</body>
</html>
EOF
fi

# Create redirects for old /2025/en/* URLs to /2025/* (English at root in 2025 too)
echo "Creating redirects for old /2025/en/ URLs..."
find "$REDIRECT_DIR/2025" -maxdepth 2 -type d | while read dir; do
    dirname=$(basename "$dir")

    # Skip the 2025 directory itself and special directories
    if [[ "$dirname" == "2025" ]] || [[ "$dirname" =~ ^(assets|search)$ ]]; then
        continue
    fi

    # Create en subdirectory structure
    mkdir -p "$REDIRECT_DIR/2025/en/$dirname"

    # Create redirect for this page
    cat > "$REDIRECT_DIR/2025/en/$dirname/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=/Top10/2025/$dirname/">
    <link rel="canonical" href="/Top10/2025/$dirname/">
</head>
<body>
    <p>Redirecting to <a href="/Top10/2025/$dirname/">OWASP Top 10:2025</a>...</p>
</body>
</html>
EOF
done

# Create redirect for /2025/en/ index
if [ -f "$REDIRECT_DIR/2025/index.html" ]; then
    mkdir -p "$REDIRECT_DIR/2025/en"
    cat > "$REDIRECT_DIR/2025/en/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0; url=/Top10/2025/">
    <link rel="canonical" href="/Top10/2025/">
</head>
<body>
    <p>Redirecting to <a href="/Top10/2025/">OWASP Top 10:2025</a>...</p>
</body>
</html>
EOF
fi

echo "HTML redirects generated successfully!"
