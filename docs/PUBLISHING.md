# Publishing Certificate Manager to GitHub

The repository is prepared for a new project named **Certificate Manager**. A suitable GitHub repository slug is **Certificate-Manager**. The chosen project license is [MIT](../LICENSE).

These instructions describe a future publication. Preparing these files does not create a remote repository, upload source or publish a running application. Choose the owning account/organization and visibility before executing publication commands.

## Review the local source

Run the checks and inspect the exact set of files that Git would include:

```sh
make test
git status --short
git ls-files --others --exclude-standard
```

Review source, documentation, translations, tests and `.github/workflows/ci.yml`. Keep `certificati`, `build/`, databases, `.smtp.key` files, environment files and private key material out of the repository. `.gitignore` excludes these local files, but review any new file types before staging. Do not use `git add -f` for local data.

The main README is in English; the complete Italian guide is at `docs/README.it.md`. The interface supports six languages; certificate subjects and user content are preserved as entered. The MIT copyright notice uses “Certificate Manager contributors”. Review that attribution before first publication if a different rights holder should be named.

## Authenticate and create the first commit

Install Git and the GitHub CLI, then authenticate interactively. Do not paste access tokens into source files, chat messages or shell commands.

```sh
gh auth login --hostname github.com
gh auth status
git add .gitignore Makefile README.md LICENSE CONTRIBUTING.md SECURITY.md .github docs scripts src tests web
git diff --cached --stat
git diff --cached
git commit -m "Initial release of Certificate Manager"
```

Inspect the staged diff before committing. Set your Git author identity using your own account details if Git requests it. The local repository is already initialized; do not reinitialize or overwrite an existing remote.

## Create the repository

After choosing owner and visibility, use GitHub's interactive creation flow:

```sh
gh repo create
```

Select the existing local repository as source, use the name `Certificate-Manager`, choose the intended owner and public/private visibility, and publish the reviewed initial commit. Alternatively, create an empty repository through GitHub and follow its instructions for adding `origin` and pushing the current branch. Do not initialize the remote with a second README or license.

Then:

1. Confirm the repository contains the MIT license and documentation, and no local data or credentials.
2. Review the first **Build and test** Actions run. The workflow runs on push, pull request and manual dispatch.
3. Enable private vulnerability reporting and update `SECURITY.md` with a maintained private contact route.
4. Add a concise description and relevant topics, then consider branch protection after the first successful CI run.

GitHub hosts the source repository. It does not run the C backend through GitHub Pages; the application still needs to be built and run locally.
