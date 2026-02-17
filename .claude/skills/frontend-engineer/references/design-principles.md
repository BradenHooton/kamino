# Modern Web Design Principles

## Visual Hierarchy

Visual hierarchy controls the order in which a user consumes information. It guides the eye through the interface, signaling importance and relationship.

### 1. Size & Scale

- Use a typographic scale (e.g., specific ratios like 1.250 Major Third).
- Headings should be significantly larger/bolder than body text.
- **Rule of Thumb**: If everything is important, nothing is.

### 2. Color & Contrast

- **Primary Action**: High contrast (e.g., solid brand color).
- **Secondary Action**: Medium contrast (e.g., outline or soft background).
- **Text**: Never pure black (`#000`). Use dark grays (e.g., `slate-900`) for less eye strain.
- **Muted Text**: Use for metadata, timestamps, or secondary info.

### 3. Spacing (The 4px Grid)

Consistent spacing is the key to a professional look.

- Use multiples of **4px** (or **0.25rem** in Tailwind).
- **Gap/Margin/Padding**: 4, 8, 12, 16, 24, 32, 48, 64px.
- **Micro-spacing**: related items (4-8px).
- **Macro-spacing**: sections (32-64px+).

## Aesthetics & "Vibe"

Modern interfaces should feel "premium" and "alive".

### 1. Depth & Elevation

- Avoid flat designs unless intentional.
- Use **subtle shadows** to create lift (`shadow-sm`, `shadow-md`).
- Use **borders** with low opacity for separation (e.g., 10% opacity white/black).

### 2. Glassmorphism & Blurs

- Use `backdrop-filter: blur()` for overlays, sticky headers, or modals.
- Combine with semi-transparent backgrounds for a modern feel.

### 3. Motion & Interaction

- **Feedback**: Every interactive element must have a `:hover` and `:active` state.
- **Transitions**: Use fast, easing curves (`cubic-bezier(0.4, 0, 0.2, 1)` or `ease-out`).
- **Duration**: `150ms` - `200ms` for micro-interactions (buttons, inputs).

## Typography

- **Font Family**: Use high-quality sans-serifs (Inter, Geist Sans, Outfit).
- **Line Height**:
  - Headings: Tight (`1.1` - `1.2`).
  - Body: Loose (`1.5` - `1.6`) for readability.
- **Letter Spacing**:
  - Uppercase: Wide (`0.05em`).
  - Headings: Tight (`-0.02em`).
  - Body: Normal.

## Layout & Composition

- **Whitespace**: Don't fear empty space. It allows content to breathe.
- **Alignment**: Align everything to a grid. Left-align text for better readability (avoid center-aligning long text).

## Anti-Patterns (What to Avoid)

1. **The "Rainbow" Effect**: Using too many competing colors. Stick to 1 primary + neutrals.
2. **Text Walls**: Break text into short paragraphs, bullet points, or cards.
3. **Inconsistent Icons**: Use a single icon set (e.g., Lucide React).
4. **Default Outlines**: Replace browser default focus rings with custom `ring` utilities.
