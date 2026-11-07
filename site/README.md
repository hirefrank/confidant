# Confidant landing page

A static-assets Cloudflare Worker (`confidant-landing`) serving
`site/public/index.html`. It serves both `/` and `/confidant/`, so it can be
hosted at a root or under a path; production routes it under
`hirefrank.com/confidant*` and `www.hirefrank.com/confidant*`
(`wrangler.jsonc`).

Preview locally from `site/` (the config pins `0.0.0.0:45456`):

```sh
npx wrangler dev
```

## Deploy path

There is no deploy step in GitHub Actions and no manual `wrangler deploy`.
The Worker is connected to this repo through the **Cloudflare dashboard's
Workers Builds integration** (Workers & Pages → `confidant-landing` →
Settings → Builds):

- root directory: `site`
- watch paths: `site/**`
- a push to `main` builds and ships production
- non-production branches get a preview build; the empty `previews` block in
  `wrangler.jsonc` exists because Wrangler refuses the preview command
  without it (branch builds fail, main stays green)

Because the watch path is `site/**`, a release that only bumps `Cargo.toml`
does not redeploy the page. Never deploy from a stale checkout with
`wrangler deploy` — it races the dashboard build and can publish old bytes
over a newer deploy.

## Version pill

The page is static, so the nav's version pill is not derived from anything:

```html
<span class="pill">v0.9.1 · Apache-2.0</span>
```

`.github/scripts/check-site-version.py` compares it against
`[workspace.package] version` in the root `Cargo.toml` and fails CI on a
mismatch, a missing pill, or a duplicate. The release prep PR bumps the pill
(`.agents/skills/confidant-release/SKILL.md`), which both satisfies the gate
and makes the release push touch `site/**` so Workers Builds ships the
updated page.
