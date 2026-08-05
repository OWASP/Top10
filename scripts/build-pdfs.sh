#!/bin/bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pdf_work_dir="$(mktemp -d "${TMPDIR:-/tmp}/owasp-top10-pdf.XXXXXX")"

# Python launched from a macOS shell may not inherit Homebrew's library path.
# WeasyPrint needs these libraries to load Pango when used as a Python module.
if [[ "$(uname -s)" == "Darwin" && -d /opt/homebrew/lib ]]; then
    export DYLD_FALLBACK_LIBRARY_PATH="/opt/homebrew/lib${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
fi

cleanup() {
    case "${pdf_work_dir}" in
        */owasp-top10-pdf.*) rm -rf -- "${pdf_work_dir}" ;;
        *) echo "Refusing to remove unexpected PDF work directory: ${pdf_work_dir}" >&2 ;;
    esac
}
trap cleanup EXIT

build_pdf() {
    version="$1"
    filename="OWASP-Top-10-${version}-en.pdf"
    version_work_dir="${pdf_work_dir}/${version}"
    staged_docs_dir="${pdf_work_dir}/${version}-docs"
    destination_dir="${repo_root}/build/${version}/downloads"

    echo "Building ${version} English PDF..."
    mkdir -p "${staged_docs_dir}"
    if [[ "${version}" == "2021" ]]; then
        cp -R "${repo_root}/${version}/docs/en/." "${staged_docs_dir}/"
        rm -f -- "${staged_docs_dir}/0x00_2021-introduction.md"
    else
        mkdir -p "${staged_docs_dir}/en"
        cp -R "${repo_root}/${version}/docs/en/." "${staged_docs_dir}/en/"
    fi
    cp -R "${repo_root}/${version}/docs/assets" "${staged_docs_dir}/assets"

    (
        cd "${repo_root}/${version}"
        PDF_DOCS_DIR="${staged_docs_dir}" \
            mkdocs build --config-file mkdocs-pdf.yml --site-dir "${version_work_dir}"
    )

    mkdir -p "${destination_dir}"
    install -m 0644 \
        "${version_work_dir}/downloads/${filename}" \
        "${destination_dir}/${filename}"
}

build_pdf 2021
build_pdf 2025

echo "PDF build complete."
echo "  - build/2021/downloads/OWASP-Top-10-2021-en.pdf"
echo "  - build/2025/downloads/OWASP-Top-10-2025-en.pdf"
