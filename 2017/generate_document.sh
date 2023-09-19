#!/bin/bash

echo "OWASP Top 10 Markdown Conversion Tool"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for pandoc
if ! command_exists pandoc; then
    echo "Error: Please install pandoc. Cannot continue."
    exit 1
fi

# Check for xelatex
if ! command_exists xelatex; then
    echo "Warning: Install xelatex to produce PDF output."
fi

echo ""

generate_pdf() {
    if command_exists xelatex; then
        echo "No PDF generated due to bugs."
    else
        echo "Could not generate PDF, missing pdflatex."
    fi
}

generate_docx() {
    pandoc -s -f markdown_github --reference-doc=../templates/reference.docx --columns 10000 -t docx -o "../OWASP-Top-10-2017-$1.docx" *.md
}

generate_html() {
    pandoc -s -f markdown_github -t html5 -o "../OWASP-Top-10-2017-$1.html" *.md
}

generate() {
    echo -n "Generating OWASP Top 10 2017 ($1)..."
    if [ -d "$1" ]; then
        cd "$1" || exit 1
        generate_docx "$1"
        generate_pdf "$1"
        generate_html "$1"
        cd ..
        echo " done."
    else
        echo " No OWASP Top 10 found in directory $1"
    fi
}

# List of languages
languages=("fr" "id" "ja" "pt-pt")

for lang in "${languages[@]}"; do
    generate "$lang"
done

echo 
echo "Generated OWASP Top 10"
