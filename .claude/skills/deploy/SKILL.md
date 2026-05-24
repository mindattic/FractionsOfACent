---
name: deploy
description: Deploy the mindattic.com/fractionsofacent/ landing page via MindAttic.Catalog. Builds index.htm from this repo's README.md and FTPS-uploads it.
---

Deploys are owned by **MindAttic.Catalog** (sibling repo at
`D:\Projects\MindAttic\MindAttic.Catalog`). One template, one build
script, one deploy script for every `mindattic.com/<slug>/` landing
page. The old per-project `scripts/cli/` pipeline is retired.

When invoked:

1. From `D:\Projects\MindAttic\MindAttic.Catalog`, run:

   ```powershell
   npm run deploy -- --only fractionsofacent
   ```

   This builds `out/fractionsofacent/index.htm` from this repo's
   `README.md` (rendered with marked + highlight.js into the canonical
   `template/index.template.htm`) and FTPS-uploads it to
   `/mindattic.com/fractionsofacent/`.

2. If `node_modules/` is missing in the Catalog repo, run
   `npm install` there first.

3. Report the FTP outcome (OK/FAIL) and the deployed URL
   (`https://mindattic.com/fractionsofacent/`).

Notes:
- Catalog's registry entry for this project lives in
  `MindAttic.Catalog/projects.json` (slug `fractionsofacent`).
- Credentials come from `MindAttic.Catalog/secrets/ftp.json`
  (gitignored). If missing, copy `secrets/ftp.json.template`.
- MindAttic.UIUX components (fonts, Cyberspace, BackHomeM) are loaded
  via jsDelivr at runtime — no per-project sync or marker-block splice.
  `projects.json -> componentsVersion` pins the ref.
- Build-only (no upload): `npm run build -- --only fractionsofacent`.
- All projects in one shot: `npm run deploy` (no `--only`).
- `scripts/cli/` in this repo is dead code awaiting removal — do not
  invoke `deploy.bat` / `deploy.ps1`.
