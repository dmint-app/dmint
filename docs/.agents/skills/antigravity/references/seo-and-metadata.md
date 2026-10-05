# SEO & Metadata Reference

## Page-Level Frontmatter

```mdx
---
title: "Page Title"                          # <title> tag, nav label
description: "One-sentence description."     # <meta name="description">, OG description
icon: "rocket"                               # Lucide icon, shown in nav
sidebarTitle: "Short Nav Label"              # override title in sidebar only
"og:image": "https://example.com/og.png"    # custom OG image
"og:title": "Custom OG Title"               # override OG title
"og:description": "Custom OG description."  # override OG description
mode: "wide"                                 # "wide" removes the right sidebar
---
```

## Site-Level SEO (docs.json)

```json
{
  "metadata": {
    "og:image": "https://example.com/og-default.png",
    "og:site_name": "Project Name Docs",
    "twitter:card": "summary_large_image",
    "twitter:site": "@handle"
  }
}
```

## Canonical URLs

Mintlify auto-generates canonical URLs from the file path. No config needed.

## Sitemap

Automatically generated at `/sitemap.xml`. No config needed.

## robots.txt

Auto-generated. To block specific paths:
```json
{
  "metadata": {
    "robots": "noindex"
  }
}
```

## Best Practices

- Every page needs a unique `title` and `description`
- `description` should be 120–160 characters
- OG images should be 1200×630px
- Use `sidebarTitle` when `title` is long (keep nav labels under 30 chars)
- Don't keyword-stuff titles; Mintlify indexes the full page content for search
