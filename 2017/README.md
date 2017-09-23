# OWASP Top 10 2017

This is the current working draft. Please do not use for day to day activities. 

We are actively seeking input on the drafts as you see them here. Please log issues. 

How to generate the PDF and Word doc. 

If using Windows, install Windows Subsystem for Linux, which is an optional install for the Win10 Creator's Update. 

Windows Subsystem for Linux, Debian and Ubuntu:

<code>
$ apt-get install pandoc
vanderaj@<redacted>:/mnt/c/Users/vande/Documents/GitHub/Top10/2017$ ./generate_document.sh
OWASP Top 10 Markdown Conversion Tool

Warning: Install xelatex to produce PDF output

Generating OWASP Top 10 2017 (en)... done.
Generating OWASP Top 10 2017 (de)... No OWASP Top 10 found in directory de
Generating OWASP Top 10 2017 (es)... No OWASP Top 10 found in directory es

Generated OWASP Top 10
</code>

To optionally create PDFs, you need Xelatex, which is a part of texlive
<code>
$ apt-get install texlive
</code>

It currently looks for `xelatex`, which is one of the sub-packages of TexLive
