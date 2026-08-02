---
name: frontend-design
description: "Design and build distinctive, high-quality frontend interfaces using HTML, CSS, and minimal JS."
---
# Frontend Design

Design and build distinctive, high-quality frontend interfaces using HTML, CSS, and minimal JS.

## Design Thinking

Before writing any code, answer these questions:
- **Purpose**: What does this page/app do? What action should the user take?
- **Audience**: Developers? General public? Enterprise? Creative professionals?
- **Constraints**: Single page? Multi-page? Must work on mobile? Accessibility requirements?
- **Aesthetic direction**: Pick one and commit to it:
  - *Minimalist* -- whitespace, restraint, typography-driven
  - *Brutalist* -- raw, bold, exposed structure, monospace
  - *Retro* -- pixel art, CRT glow, vintage color palettes
  - *Organic* -- soft shapes, natural colors, hand-drawn feel
  - *Luxury* -- dark backgrounds, serif fonts, generous spacing
  - *Playful* -- bright colors, rounded shapes, animation-heavy
  - *Editorial* -- magazine-style grids, strong typographic hierarchy

Ask: what makes this design *memorable*? If it could belong to any generic template, push further.

## Typography

Never default to Arial, Inter, Roboto, Helvetica, or system fonts. Typography is the single biggest differentiator.

Load distinctive fonts via Google Fonts CDN:
```html
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Sans:wght@400;500;700&display=swap" rel="stylesheet">
```

Pair a **display font** (headings) with a **body font** (text):
- Luxury: `Playfair Display` + `Source Sans 3`
- Technical: `JetBrains Mono` + `Inter`
- Editorial: `Fraunces` + `Commissioner`
- Playful: `Baloo 2` + `Nunito`
- Brutalist: `Space Mono` + `Space Grotesk`

Set a clear typographic scale:
```css
h1 { font-size: clamp(2.5rem, 5vw, 4.5rem); line-height: 1.1; letter-spacing: -0.02em; }
h2 { font-size: clamp(1.8rem, 3vw, 2.8rem); line-height: 1.2; }
body { font-size: 1.125rem; line-height: 1.6; }
```

## Color & Theme

Define a cohesive palette with CSS custom properties. One bold dominant color, one accent, neutral tones:
```css
:root {
  --color-bg: #0a0a0a;
  --color-surface: #141414;
  --color-text: #e8e4de;
  --color-text-muted: #8a8680;
  --color-accent: #ff5722;
  --color-accent-hover: #ff7043;
}
```

Guidelines:
- Bold dominant + sharp accent > timid evenly-distributed palettes
- Dark themes: avoid pure `#000` and `#fff` -- use off-blacks and warm whites
- Light themes: avoid sterile grays -- add warmth (cream, stone, sage)
- Avoid the cliched AI aesthetic: purple gradients on white, blue-to-teal, frosted glass everywhere
- Use `color-mix()` for opacity variants: `color-mix(in srgb, var(--color-accent) 20%, transparent)`

## Layout

Use CSS Grid for page structure, Flexbox for component alignment:
```css
.page { display: grid; grid-template-columns: 1fr min(65ch, 90%) 1fr; }
.page > * { grid-column: 2; }
.page > .full-bleed { grid-column: 1 / -1; }

.hero { display: grid; grid-template-columns: 1.2fr 1fr; gap: 4rem; align-items: center; }
```

Responsive breakpoints -- mobile-first:
```css
.grid { display: grid; grid-template-columns: 1fr; gap: 2rem; }
@media (min-width: 640px) { .grid { grid-template-columns: repeat(2, 1fr); } }
@media (min-width: 1024px) { .grid { grid-template-columns: repeat(3, 1fr); } }
```

Use interesting spatial composition: asymmetric grids, overlapping elements with negative margins, generous whitespace (`padding: 6rem 0` not `1rem`).

## Motion & Interaction

CSS transitions for hover states:
```css
.card {
  transition: transform 0.3s ease, box-shadow 0.3s ease;
}
.card:hover {
  transform: translateY(-4px);
  box-shadow: 0 12px 40px rgba(0,0,0,0.15);
}
```

Staggered entrance animations:
```css
@keyframes fadeUp {
  from { opacity: 0; transform: translateY(24px); }
  to { opacity: 1; transform: translateY(0); }
}
.card { animation: fadeUp 0.6s ease both; }
.card:nth-child(2) { animation-delay: 0.1s; }
.card:nth-child(3) { animation-delay: 0.2s; }
```

Guidelines:
- Hover states should surprise: color shifts, underline animations, scale changes
- Keep durations 0.2-0.5s -- anything longer feels sluggish
- Use `prefers-reduced-motion` to disable animations for accessibility
- Animations should reinforce hierarchy, not distract

## Implementation

### Semantic HTML5 Structure
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Page Title</title>
  <link rel="stylesheet" href="styles.css">
  <link href="https://fonts.googleapis.com/css2?family=..." rel="stylesheet">
</head>
<body>
  <header>...</header>
  <main>
    <section class="hero">...</section>
    <section class="features">...</section>
  </main>
  <footer>...</footer>
</body>
</html>
```

- CSS-first: achieve visual effects with CSS before reaching for JS
- Mobile-first: start with single-column, add complexity at wider breakpoints
- Accessibility: `alt` on images, `:focus-visible` styles, semantic elements, check contrast ratios (4.5:1 minimum)
- Preview in a browser: `bash: python3 -m http.server 8080` then use `web_fetch` to verify the page loads

## Anti-Patterns

Avoid these common traps:
- **Generic AI aesthetic**: Inter font, purple/blue gradients, frosted glass cards, "Powered by AI" feel
- **Rounded-corner syndrome**: not everything needs `border-radius: 12px` and `box-shadow`
- **Template sameness**: every section looks like hero > 3-card grid > CTA > footer
- **Ignoring mobile**: always test at 375px width
- **Color cowardice**: gray-on-white with one pale blue accent is not a palette
- **Font neglect**: spending hours on layout but leaving the browser default font stack

## Skill Chaining

- Use **web-research** to study design references and current trends before starting
- Use **web-fetch** to pull color palettes from sites like coolors.co or inspect reference pages
- After building, test in multiple viewports: `bash: python3 -m http.server 8080 &` then verify structure
- Use **node-dev** if the project needs a build step (Vite, Tailwind CLI)
