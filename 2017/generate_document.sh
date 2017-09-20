#!/bin/bash

type pandoc >/dev/null 2>&1 || { echo >&2 "I require pandoc but it's not installed.  Aborting."; exit 1; }

# English
cd en
pandoc -f markdown_github --columns 10000 -t docx -o ../OWASP-Top-10-2017-en.docx *.md
#pandoc --latex-engine=xelatex -o ../OWASP-Top-10-2017-en.pdf *.md
cd ..

# Spanish
cd es
#pandoc -f markdown_github --columns 10000 -t docx -o ../OWASP-Top-10-2017-es.docx *.md
#pandoc --latex-engine=xelatex -o ../OWASP-Top-10-2017-es.pdf *.md
cd ..

