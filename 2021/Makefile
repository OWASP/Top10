.PHONY: help
.SILENT:

help:
	@grep -E '^[a-zA-Z_-]+:.*?# .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?# "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install-python-requirements:  # Install Python 3 required libraries
	python -m pip install -r requirements.txt

install-python-requirements-test:  # Install Python 3 required libraries
	python -m pip install -r requirements-test.txt

generate-site:  # Builds ./2021
	mkdocs build

serve:  # Build and hot-reloads ./2021
	mkdocs serve

check-links:  # Checks for dead links
	python -m linkcheckmd
