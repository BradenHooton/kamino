# Frontend Tech Stack & Implementation Patterns

This reference documents the core frontend technologies and how they integrate to build robust, type-safe web applications.

## Core Framework & Language

- **React**: Functional components with hooks.
- **TypeScript**: Strict type checking, interface definitions for props and data.

## State Management & Data Fetching

- **TanStack Query (React Query)**:
  - Use `useQuery` for fetching and `useMutation` for updates.
  - Centralize query keys in a constant or factory.
  - Implement optimistic updates for better UX.
- **Zustand**:
  - Use for global UI state (modals, user session, themes).
  - Keep stores small and focused.
  - Use selectors to prevent unnecessary re-renders.

## Routing & Forms

- **TanStack Router**:
  - File-based routing for large apps.
  - Type-safe search params and loaders.
  - Integrated breadcrumbs and layout nesting.
- **React Hook Form**:
  - Use with the `Zod` resolver for unified validation.
  - Prefer uncontrolled components for performance where possible.
  - Utilize `useFormContext` for complex, multi-step forms.

## Validation & Schemas

- **Zod**:
  - Define single source of truth schemas for API responses and form data.
  - Shared schemas between frontend and backend (via JSON/DTO matching).

## UI & Styling

- **Radix UI**:
  - Accessible, unstyled primitives for complex components (Dialog, Popover, Select).
- **Tailwind CSS**:
  - Utility-first styling.
  - Use `@apply` sparingly; prefer component composition.
- **CSS Modules**:
  - Use for highly custom logic or when Tailwind becomes too verbose.
- **Design Tokens**:
  - Define colors, spacing, and typography in `tailwind.config.ts`.
  - Use CSS variables for values that change at runtime (e.g., dynamic themes).

## Integration with Backend

- Match DTOs with Zod schemas.
- Dual-Token Pattern for Auth: Handle HttpOnly cookies and refresh logic.
- Standardized error handling: Map backend error codes to user-friendly messages.
