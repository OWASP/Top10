window.addEventListener("DOMContentLoaded", _ => {
    const MutationObserver = window.MutationObserver || window.WebKitMutationObserver;
    const observer = new MutationObserver((mutations, _) => {
        const nodesForRemoval = [];
        for (const record of mutations) {
            for (const liNode of record.addedNodes) {
                let removeNode = false;
                for (const anchor of liNode.querySelectorAll("a")) {
                    const searchResultLocale = getSearchResultLocaleFromAnchor(anchor);
                    const isSearchResultFromCurrentPageLocale = searchResultLocale === document.querySelector('html[lang]').lang;
                    if (!isSearchResultFromCurrentPageLocale) {
                        removeNode = true;
                        continue;
                    }
                }

                if (removeNode) {
                    nodesForRemoval.push(liNode);
                }
            }
        }

        for (const node of nodesForRemoval) {
            node.remove();
        }

        const amountDisplay = document.querySelector(".md-search-result__meta");
        const result = document.querySelector('.md-search-result__list').childNodes.length
        amountDisplay.textContent = amountDisplay.textContent.replace(/\d+/i, result.toString());
    });

    observer.observe(document.querySelector(".md-search-result__list"), { childList: true });
});

function getSearchResultLocaleFromAnchor(anchor) {
    const localeSegment = anchor.href.split("/")[3];
    // Note that we make an assumption here that the only length 2
    // link segments will be the locale immediately after the site's base URL.
    return (localeSegment.length === 2 || localeSegment.length === 5 || localeSegment.length === 7) ? localeSegment : 'en';
}