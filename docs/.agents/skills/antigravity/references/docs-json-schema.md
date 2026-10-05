# docs.json Full Schema Reference

## Top-Level Fields

```json
{
  "$schema": "https://mintlify.com/docs.json",

  "name": "string — site name shown in browser tab",
  "theme": "mint | quill | venus | prism | linden | willow | maple | palm",

  "logo": {
    "light": "/logo/light.svg",
    "dark": "/logo/dark.svg",
    "href": "https://yoursite.com"
  },

  "favicon": "/favicon.svg",

  "colors": {
    "primary": "#hex",
    "light": "#hex",
    "dark": "#hex",
    "background": {
      "light": "#hex",
      "dark": "#hex"
    }
  },

  "topbarLinks": [
    { "name": "string", "url": "string" }
  ],

  "topbarCtaButton": {
    "name": "string",
    "url": "string",
    "style": "roundedRectangle | pill"
  },

  "primaryTab": {
    "name": "string — label for the first nav tab"
  },

  "tabs": [
    {
      "name": "string",
      "url": "string — base path for this tab"
    }
  ],

  "anchors": [
    {
      "name": "string",
      "icon": "lucide-icon-name",
      "url": "string"
    }
  ],

  "navigation": [
    {
      "group": "string — group label",
      "pages": [
        "path/to/page",
        {
          "group": "Nested Group",
          "pages": ["path/to/nested-page"]
        }
      ]
    }
  ],

  "footerSocials": {
    "github": "url",
    "twitter": "url",
    "linkedin": "url",
    "discord": "url",
    "slack": "url",
    "youtube": "url",
    "website": "url"
  },

  "openapi": ["openapi.yaml"],

  "api": {
    "baseUrl": "https://api.example.com",
    "auth": {
      "method": "bearer | basic | key",
      "name": "Authorization"
    },
    "playground": {
      "mode": "show | hide | simple"
    }
  },

  "search": {
    "prompt": "string — placeholder text in search bar"
  },

  "modeToggle": {
    "default": "light | dark",
    "isHidden": false
  },

  "backgroundImage": "/images/bg.png",

  "integrations": {
    "intercom": "app-id",
    "ga4": "G-XXXXXXXX",
    "posthog": {
      "apiKey": "phc_xxx",
      "apiHost": "https://app.posthog.com"
    }
  },

  "redirects": [
    {
      "source": "/old-path",
      "destination": "/new-path"
    }
  ]
}
```

---

## Themes

| Theme | Character |
|-------|-----------|
| `mint` | Clean, green-accented default |
| `quill` | Editorial, text-forward |
| `venus` | Modern, bold |
| `prism` | High-contrast, vibrant |
| `linden` | Warm, earthy |
| `willow` | Soft, neutral |
| `maple` | Warm amber |
| `palm` | Tropical, casual |

---

## Navigation — Nested Groups (one level deep)

```json
{
  "group": "Guides",
  "pages": [
    "guides/introduction",
    {
      "group": "Advanced",
      "pages": [
        "guides/advanced/caching",
        "guides/advanced/performance"
      ]
    }
  ]
}
```

---

## Multi-Tab Sites

Use `tabs` to split docs into separate tab bars (e.g. Docs | API | SDK):

```json
"tabs": [
  { "name": "Documentation", "url": "docs" },
  { "name": "API Reference", "url": "api-reference" },
  { "name": "SDK", "url": "sdk" }
]
```

Each tab has its own navigation group rooted at its `url`.

---

## OpenAPI Integration

```json
"openapi": ["api/openapi.yaml"]
```

Pages auto-generated from OpenAPI have the path: `api-reference/<tag>/<operationId>`.
Override with a custom `.mdx` file at the same path.

---

## Custom CSS

```json
"custom": {
  "css": "/custom.css"
}
```

In `/custom.css`:
```css
:root {
  --font-family-heading: 'YourFont', sans-serif;
}

.dark {
  --background-color: #0f0f13;
}
```
