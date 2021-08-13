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
        pandoc -N --template ../templates/template.tex --variable mainfont="Merriweather" --variable sansfont="Roboto" --variable monofont="Source Code Pro for Powerline" --variable fontsize=10pt --variable version=1.17.2 --pdf-engine=xelatex --toc -fmarkdown-implicit_figures -o "../OWASP-Top-10-2017-$1.pdf" *.md
        # echo " no PDF generated due to bugs"
    else
        echo " could not generate PDF, missing pdflatex"
    fi
}

generate_docx() {
    pandoc -s -f gfm --reference-doc=../templates/reference.docx --metadata title="OWASP Top 10 2017" --columns 10000 -t docx -o "../OWASP-Top-10-2017-$1.docx" *.md
}

generate_odt() {
    pandoc -s -f gfm --reference-doc=../templates/reference.odt --metadata title="OWASP Top 10 2017" --columns 10000 -t odt -o "../OWASP-Top-10-2017-$1.odt" *.md
}

generate_html() {
    pandoc -s -f gfm --metadata title="OWASP Top 10 2017" -t html5 -o "../OWASP-Top-10-2017-$1.html" *.md
}

generate() {
    echo -n "Generating OWASP Top 10 2017 ($1)..."
    if [ -d "$1" ]; 
    then
        cd "$1"
        generate_odt $1
        generate_docx $1
        # generate_pdf $1
        generate_html $1
        cd ..
        echo " done."
    else
        echo " No OWASP Top 10 found in directory $1"
    fi
}

# English
generate "en"

# German
generate "de"

# Spanish
generate "es"

# Farsi
generate "es"

# French 
generate "fr"

# Hebrew
generate "he"

# Bahasa indonesia
generate "id"

# Japanese
generate "ja"

# Korean - no source files
# generate "ko"

# Portuguese - Brazil
generate "pt-br"

# Portuguese - Portugal
generate "pt-pt"

# Russian
generate "ru"

# Turkish
generate "tr"

echo 
echo "Generated OWASP Top 10"
