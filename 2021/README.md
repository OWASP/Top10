# OWASP Top 10 2021

Final Release

## Building a local copy

Make sure Python 3 is installed. Optionally create a virtual environment.

```sh
# Install dependencies
make install-python-requirements
```

```sh
# Build HTML
make generate-site
# Browse /2021/site
```

### Test it locally

Alternatively you can spin up a hot-reloading server:

```sh
make serve
```

Once you are happy, check in your changes as a branch / PR and let someone on the main team know. We'll review your changes, and merge and redeploy.

### Deploy to gh-pages

This only works if you have commit privileges on master and Git is correctly setup in your environment.

```sh
cd 2021
mkdocs gh-deploy
```

### Translating the OWASP Top 10 2021

- Join the OWASP Slack and join the #top-10-translations channel. Let folks know what language you are doing. Someone might already be working on it.
- Fork and clone the Top 10 repo
- Follow the installation and local test instructions above
- Create a new branch for your language (something like 2021-fr)
- Add your translation to the plugin / navigation area in mkdocs.yml
- Test your translation locally by running a local server (see above)
- When you're ready, create a pull request against the OWASP Top 10 repo, and let us know it's ready for deployment
