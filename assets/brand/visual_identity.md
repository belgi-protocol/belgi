# BELGI Visual Identity (Basic)

This document defines minimal, stable rules for BELGI visual identity in docs, web pages, and slideware.

## Brand assets

Logos live in `assets/brand/`:
- `logo-primary.svg` — default for light backgrounds
- `logo-reverse.svg` — default for dark backgrounds
- `icon-only.svg` — square/compact usage on light backgrounds
- `icon-only-reverse.svg` — square/compact usage on dark backgrounds

Recommended README/GitHub usage: prefer theme-aware `<picture>` to select primary vs reverse.

## Primary colors

| Token | Hex | Notes |
|---|---|---|
| Navy 900 | `#0B1F3B` | Deep base (background, headers) |
| Blue 800 | `#0A2A66` | Accent (links, callouts, UI emphasis) |
| White | `#FFFFFF` | Foreground on dark backgrounds |


### Suggested CSS variables

```css
:root {
  --belgi-navy-900: #0B1F3B;
  --belgi-blue-800: #0A2A66;
  --belgi-white: #FFFFFF;
}
```

## Usage rules (minimum)

### Background selection
- On white backgrounds use `logo-primary.svg`.
- On dark backgrounds (Navy 900 / Blue 800): use `logo-reverse.svg`.

### Clear space
- Keep at least 1× the logo mark height of padding around the logo (no text, borders, or other marks inside this zone).

### Minimum size
- Do not render the full logo below 120px width (use icon-only marks for smaller sizes).

### Do / Don’t
- Do keep the SVG unmodified (no recolors, strokes, shadows, or gradients).
- Do preserve aspect ratio.
- Don’t place the primary logo on dark backgrounds.
- Don’t crop the wordmark.

## Accessibility note

When using Blue 800 as a link/accent color, ensure sufficient contrast against the chosen background.
