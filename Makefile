.PHONY: help
.SILENT:

help:
	@grep -E '^[a-zA-Z_-]+:.*?# .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?# "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install-python-requirements:  # Install Python 3 required libraries
	python3 -m pip install -r requirements.txt

generate-site:  # Use custom-script to generate the website
	(cd 2021 && mkdocs build)

serve:  # Start's a Python http.server on port 8000 serving the content of ./generated/site
	(cd 2021 && mkdocs serve)
