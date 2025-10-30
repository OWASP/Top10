.PHONY: help
.SILENT: 

year := 2025
port := 8000

DEBUG := echo DEBUG:
DEBUG := 

# Calculate current directory - see https://stackoverflow.com/a/18137056/721263
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(dir $(mkfile_path))

# Keep this in sync with .gitignore
# !!WARNING!! No trailing whitespace for venvdir!!
venvdir := $(current_dir)/venv
activate := . $(venvdir)/bin/activate

help:
	@grep -E '^[a-zA-Z_-]+:.*?# .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?# "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install-python-requirements:  # Install Python 3 required libraries
	if [ \! -f bin/activate ]; then \
		echo Creating Python virtual environment; \
		$(DEBUG) python3 -m venv $(venvdir); \
	else \
		echo Using existing Python virtual environment in ; \
	fi 
	($(DEBUG) $(activate) && $(DEBUG) python3 -m pip install -r requirements.txt && $(DEBUG) python3 -m pip install --upgrade pip)

generate:  # Use custom-script to generate the website
	($(DEBUG) $(activate) && $(DEBUG) cd $(year) && $(DEBUG) mkdocs build)

serve:  # Start's a Python http.server on port 8000 serving the content of ./generated/site
	($(DEBUG) $(activate) && $(DEBUG) cd $(year) && $(DEBUG) mkdocs serve -a localhost:$(port))

all: install-python-requirements generate serve  # Install requirements, generate the site, then serve it

genserve: generate serve  # Generate the site, then serve it