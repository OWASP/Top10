#!/bin/bash

echo "OWASP Top 10 Markdown Conversion Tool"
echo ""

function command_exists () {
    command -v $1 >/dev/null 2>&1;
}

if ! command_exists pandoc; then
    echo "Error: Please install pandoc. Cannot continue"
    exit;
fi

if ! command_exists xelatex; then
    echo "Warning: Install xelatex to produce PDF output"
fi

echo ""

generate_pdf() {
    if command_exists xelatex; then
        pandoc --latex-engine=xelatex -o "../OWASP-Top-10-2017-$1.pdf" *.md
    fi
}

generate_docx() {
    pandoc -f markdown_github --reference-docx=../reference.docx --columns 10000 -t docx -o "../OWASP-Top-10-2017-$1.docx" *.md
}

generate() {
    echo -n "Generating OWASP Top 10 2017 ($1)..."
    if [ -d "$1" ]; 
    then
        cd "$1"
        generate_docx $1
        generate_pdf $1
        cd ..
        echo " done."
    else
        echo " No OWASP Top 10 found in directory $1"
    fi
}

# Arabic
#generate "ar"

# Brazil
#generate "br"

# Chinese 
#generate "cn"

# Czech
#generate "cz"

# English
generate "en"

# French 
#generate "fr"

# German
generate "de"

# Hebrew
#generate "heb"

# Italian
#generate "it"

# Japanese
#generate "jp"

# Korean
#generate "kr"

# Spanish
generate "es"

# Ukraine
#generate "ukr"

echo 
echo "Generated OWASP Top 10"