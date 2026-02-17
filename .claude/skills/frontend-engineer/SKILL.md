---
name: frontend-engineer
description: Expert frontend development using React, TypeScript, and modern ecosystem tools. Use this skill when building web applications, admin panels, or UI components. It emphasizes type-safety (TanStack, Zod), visual excellence (anti-vibe-coding, Radix), and seamless backend integration.
---

# Frontend Engineer

Professional guide for building high-quality, type-safe, and visually stunning web applications.

## Core Capabilities

1.  **Modern React Architecture**: Building scalable applications with React 18+, TypeScript, and functional components.
2.  **Type-Safe State & Data**: Implementing TanStack Query for server state, Zustand for client state, and Zod for schema validation.
3.  **Advanced Routing**: Leveraging TanStack Router for file-based, type-safe navigation and data fetching.
4.  **Premium UI/UX Design**: Creating sophisticated interfaces using Radix UI primitives and Tailwind CSS, adhering to strict visual hierarchy and design tokens.
5.  **Admin Panel Excellence**: Developing powerful internal tools with standardized CRUD patterns and RBAC.

## Workflows

### 1. Project Initialization & Setup

When starting a new frontend project or module:

- Define the directory structure (e.g., `src/components`, `src/hooks`, `src/features`).
- Configure TanStack Router and Query providers.
- Establish the design system in `tailwind.config.ts`.

### 2. Feature Implementation

For each new feature:

- **Define Schemas**: Create Zod schemas for API responses and forms.
- **Data Hook**: Create a custom hook using TanStack Query for data fetching/mutations.
- **Component Logic**: Implement the UI using React Hook Form and Radix primitives.
- **Design Polish**: Apply Tailwind utility classes following the [Design Principles](references/design-principles.md).

### 3. Backend Integration

- Synchronize frontend DTOs with backend structs.
- Implement auth interceptors for Dual-Token (JWT + Cookie) patterns.
- Ensure consistent error handling across the stack.

## Guidelines & References

Refer to these specialized guides for detailed implementation patterns:

- **[Tech Stack & Patterns](references/tech-stack.md)**: Deep dive into library usage (React, TanStack, Zustand, Zod).
- **[Design Principles](references/design-principles.md)**: Standards for visual excellence, hierarchy, and avoiding generic "vibe-coded" styles.
- **[Admin Panel Architecture](references/admin-panels.md)**: Specialized patterns for building internal management UIs.

## Best Practices

- **Strict TypeScript**: No `any`. Use generics for reusable components.
- **Component Atoms**: Build small, focused components before assembling complex views.
- **Self-Documenting Code**: Use clear naming conventions for props, states, and hooks.
- **Performance**: Use memoization (`useMemo`, `useCallback`) only where measurement shows necessity.
