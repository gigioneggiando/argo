# Research source

This directory is a public build input. It must never contain private disclosure material.

`manifest.json` is the explicit publication allow-list. The builder reads only slugs in
`approvedArticles`; a folder existing under `articles/` is not permission to publish it. Add a slug
only after Luigi has approved the final article and every material detail is already supported by a
public, unauthenticated upstream record.

Each approved slug resolves to:

```
articles/<stable-slug>/article.json
articles/<stable-slug>/body.html
```

Copy `_template/` only after drafting in `../../../../argo-publication/` and completing the public
evidence review. `research/` at the repository root is generated output; never edit it by hand.

Run:

```
node build.mjs
node verify-research.mjs
```

To inspect a private local draft without adding it to the allow-list or generated public pages:

```
node preview-research.mjs ../argo-publication/drafts/<slug>
```

This writes an ignored `.research-preview/` directory. Preview validation still enforces the article
structure and public-data safety checks, but production builds continue to require Luigi's explicit
approval metadata and a manifest entry.

The research navigation and generated output remain absent while the allow-list is empty.
