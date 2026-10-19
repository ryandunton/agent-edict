# AgentEdict public site

This is a dependency-free static site: `index.html`, the icons in `assets/`, and the configuration builder in `builder/`.

## Publishing

The `pages` workflow (`.github/workflows/pages.yml`) builds the builder's WebAssembly and publishes this folder to GitHub Pages on every push to `main`, so changes go live when they merge. GitHub Pages serves it at https://agent-edict.com, set as the repository's custom domain. Review project facts, links, and CLI captures before merging.

To publish elsewhere, such as Cloudflare Pages, set the build command to `make builder` and the output directory to `public`. See Cloudflare's [Git integration](https://developers.cloudflare.com/pages/configuration/git-integration/) and [Direct Upload](https://developers.cloudflare.com/pages/get-started/direct-upload/) guides.

## Real output

The page's claims of real output are literal:

- The "One profile in. Native files out." example embeds the compiler's exact output for `examples/site-demo/team-guardrails.yaml` and `team-guardrails.native.yaml` on each operating system, at the destination paths the daemon installs them to. Regenerate it whenever an adapter's output changes.
- The terminal captures are the exact lines printed by the commands they show, run against `examples/native/`.

These runs validate generated artifacts and evaluator responses. They do not validate behavior inside installed AI clients.
