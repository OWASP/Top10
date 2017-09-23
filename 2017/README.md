# OWASP Top 10 2017

This is the current working draft. Please do not use for day to day activities. 

Please review for content, context, accuracy, links, spelling, and examples, and [log issues](https://github.com/OWASP/Top10/issues).

** The markdown, Word, and PDF versions is not pretty or final. We are working on content, not formatting **

## How to generate the PDF and Word documents

If using Windows, install Windows Subsystem for Linux, which is an optional install for the Win10 Creator's Update. 

Windows Subsystem for Linux, Debian and Ubuntu:

<pre>
$ apt-get install pandoc
vanderaj@<redacted>:/mnt/c/Users/vande/Documents/GitHub/Top10/2017$ ./generate_document.sh
OWASP Top 10 Markdown Conversion Tool

Warning: Install xelatex to produce PDF output

Generating OWASP Top 10 2017 (en)... done.
Generating OWASP Top 10 2017 (de)... No OWASP Top 10 found in directory de
Generating OWASP Top 10 2017 (es)... No OWASP Top 10 found in directory es

Generated OWASP Top 10
</pre>

To optionally create PDFs, you need Xelatex, which is a part of texlive
<code>
$ apt-get install texlive
</code>

It currently looks for `xelatex`, which is one of the sub-packages of TexLive


