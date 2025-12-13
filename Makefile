.PHONY: help all genserve
.SILENT:

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
	@grep -E '^[a-zA-Z0-9_-]+:.*?# .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?# "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install-python-requirements:  # Install Python 3 required libraries
	if [ \! -f bin/activate ]; then \
		echo Creating Python virtual environment; \
		$(DEBUG) python3 -m venv $(venvdir); \
	else \
		echo Using existing Python virtual environment in ; \
	fi 
	($(DEBUG) $(activate) && $(DEBUG) python3 -m pip install -r requirements.txt && $(DEBUG) python3 -m pip install --upgrade pip)

build-2021:  # Build 2021 site only
	($(activate) && cd 2021 && mkdocs build --site-dir ../build/2021)

build-2025:  # Build 2025 site only
	($(activate) && cd 2025 && mkdocs build --site-dir ../build/2025)

build-all:  # Build both sites with redirects
	./scripts/build-all.sh

build: build-all  # Alias for build-all

clean-2021:  # Clean 2021 build output
	rm -rf build/2021

clean-2025:  # Clean 2025 build output
	rm -rf build/2025

clean-all:  # Clean all build output
	rm -rf build/

clean: clean-all  # Alias for clean-all

serve-2021:  # Serve 2021 site
	($(activate) && cd 2021 && mkdocs serve -a localhost:8000)

serve-2025:  # Serve 2025 site
	($(activate) && cd 2025 && mkdocs serve -a localhost:8001)

serve: build-all  # Serve both 2021 and 2025 sites from build directory
	@echo "Starting server on http://localhost:8000"
	@echo "  - 2021 site: http://localhost:8000/2021/"
	@echo "  - 2025 site: http://localhost:8000/2025/"
	@echo ""
	(cd build && python3 -m http.server 8000)

generate: build-2021  # Maintain backward compatibility (keep existing)

all: install-python-requirements build-all  # Install requirements and build both sites

publish: build-all  # Deploy both sites to GitHub Pages
	($(activate) && cd build && git init && git add -A && git commit -m "Deploy both 2021 and 2025 sites" && git push -f git@github.com:OWASP/Top10.git master:gh-pages)

