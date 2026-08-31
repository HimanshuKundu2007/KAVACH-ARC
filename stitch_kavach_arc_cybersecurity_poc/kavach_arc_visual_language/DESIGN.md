---
name: KAVACH-ARC Visual Language
colors:
  surface: '#10141a'
  surface-dim: '#10141a'
  surface-bright: '#353940'
  surface-container-lowest: '#0a0e14'
  surface-container-low: '#181c22'
  surface-container: '#1c2026'
  surface-container-high: '#262a31'
  surface-container-highest: '#31353c'
  on-surface: '#dfe2eb'
  on-surface-variant: '#bbc9cf'
  inverse-surface: '#dfe2eb'
  inverse-on-surface: '#2d3137'
  outline: '#859399'
  outline-variant: '#3c494e'
  surface-tint: '#4cd6ff'
  primary: '#a4e6ff'
  on-primary: '#003543'
  primary-container: '#00d1ff'
  on-primary-container: '#00566a'
  inverse-primary: '#00677f'
  secondary: '#c1c7d2'
  on-secondary: '#2b3139'
  secondary-container: '#464c55'
  on-secondary-container: '#b6bcc7'
  tertiary: '#ffd59c'
  on-tertiary: '#442b00'
  tertiary-container: '#feb127'
  on-tertiary-container: '#6b4700'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#b7eaff'
  primary-fixed-dim: '#4cd6ff'
  on-primary-fixed: '#001f28'
  on-primary-fixed-variant: '#004e60'
  secondary-fixed: '#dde3ee'
  secondary-fixed-dim: '#c1c7d2'
  on-secondary-fixed: '#161c24'
  on-secondary-fixed-variant: '#414750'
  tertiary-fixed: '#ffddb1'
  tertiary-fixed-dim: '#ffba49'
  on-tertiary-fixed: '#291800'
  on-tertiary-fixed-variant: '#624000'
  background: '#10141a'
  on-background: '#dfe2eb'
  surface-variant: '#31353c'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  title-sm:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '450'
    lineHeight: 20px
  label-caps:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  gutter: 16px
  margin: 24px
  container-max: 1440px
---

## Brand & Style
The design system is engineered for high-stakes cybersecurity environments where precision, authority, and data density are paramount. The personality is disciplined and analytical, stripping away decorative "cyber" tropes in favor of professional utility.

The aesthetic follows a **Modern Minimalist** approach with a **Technical** edge. It prioritizes information hierarchy through crisp geometry, ample but controlled negative space, and a logical use of color to indicate system status. The interface should feel like a high-performance instrument—unobtrusive when things are normal, and commanding when action is required.

## Colors
The palette is rooted in deep, monochromatic foundations to reduce eye strain during prolonged monitoring. 

- **Foundation**: Use `#0A0E14` for the primary application canvas. Use `#121820` for elevated surfaces like cards, panels, and sidebars.
- **Accent**: Cyan (`#00D1FF`) is used sparingly for primary actions and active states to maintain professional focus.
- **Semantics**: Status colors follow a strict functional logic. Use High-Contrast variants for text and subtle desaturated versions for background indicators to ensure legibility.
- **Borders**: All borders must use `#1F2937` to maintain a structural grid without creating visual noise.

## Typography
Typography is the core of the design system's utility. 

- **Inter** is the workhorse for all UI labels, navigation, and body text. 
- **JetBrains Mono** is strictly reserved for technical data, code diffs, logs, and evidence hashes to ensure character distinction (e.g., `0` vs `O`).
- **Data Density**: Use `body-sm` for secondary metadata. Ensure line heights are tight but legible to maximize information per screen.
- **Labels**: Use `label-caps` for section headers in sidebars and small metadata tags.

## Layout & Spacing
The layout follows a **Fixed-Fluid Hybrid** model. Navigation and sidebars are fixed-width to ensure tool accessibility, while primary data workspaces (like code viewers and timelines) fluidly expand.

- **Grid**: A 12-column grid is used for dashboard layouts, while technical views use a 4px baseline rhythm.
- **Density**: Use compact padding (8px or 12px) within cards to accommodate complex data sets.
- **Breakpoints**: 
  - Desktop: 1440px+ (Standard working environment)
  - Laptop: 1024px (Condensed view, sidebars may collapse)

## Elevation & Depth
This design system avoids shadows to maintain a "flat-technical" professional aesthetic. Depth is communicated via **Tonal Layers** and **Low-Contrast Outlines**.

- **Level 0 (Background)**: `#0A0E14` (The void/base).
- **Level 1 (Cards/Panels)**: `#121820` with a 1px solid border of `#1F2937`.
- **Level 2 (Modals/Popovers)**: `#1A222C` with a slightly brighter border of `#374151` to separate the element from the panel below.
- **Active State**: Elements being hovered or focused should use a subtle background shift or a primary cyan left-border accent rather than a drop shadow.

## Shapes
Shapes are conservative and architectural. 

- **Base Radius**: 4px (`rounded-sm`) for buttons, input fields, and cards. This maintains a sharp, precise look while avoiding the harshness of 0px corners.
- **Status Indicators**: Use 2px radius for small status pips or 100px (full pill) for status tags.
- **Interactive Areas**: Visual affordance for clickability is provided by color shifts rather than aggressive rounding.

## Components

### Pipeline Status Trackers
Linear horizontal or vertical nodes. Active nodes use a `primary` cyan pulse (1px glow); completed nodes use `status_success`; failed nodes use `status_critical`. Connecting lines should be 1px wide.

### Code Diff Viewers
Use `code-md` typography. Backgrounds for additions: `#065F46` (dark green) at 20% opacity. Deletions: `#991B1B` (dark red) at 20% opacity. Line numbers must be right-aligned in a dedicated gutter.

### Evidence Timelines
A vertical 1px line with circular markers. Each marker's color corresponds to the event's severity. Text should include a timestamp in `code-md` for precision.

### Buttons & Inputs
- **Primary**: Cyan background, `#0A0E14` text. No gradients.
- **Ghost/Secondary**: Transparent background, 1px `#1F2937` border, white text.
- **Inputs**: Background `#0A0E14`, border `#1F2937`. On focus, the border changes to `primary` cyan with no outer glow.

### Cards
Cards are the primary container. They must have a title bar with a `#1F2937` bottom border to separate the header from the content body. Header text should use `label-caps`.