# TanStack Router Reference

## Overview

TanStack Router is a fully type-safe router for React application. We use **File-Based Routing** for scalability.

## Core Concepts

### 1. File Structure

Follow the recursive file-route pattern in `src/routes`:

```text
src/routes/
├── __root.tsx      # Root layout
├── index.tsx       # /
├── about.tsx       # /about
├── users/
│   ├── route.tsx   # /users layout
│   ├── index.tsx   # /users/
│   └── $userId.tsx # /users/:userId
```

### 2. Component Structure

Each route file typically exports:

1.  **`FileRoute`**: The route configuration.
2.  **`Loader`**: Data fetching (optional).
3.  **`Component`**: The UI.

```tsx
import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

// 1. Validation Schema for Search Params
const userSearchSchema = z.object({
  page: z.number().catch(1),
  sort: z.enum(["asc", "desc"]).catch("asc"),
});

// 2. Route Definition
export const Route = createFileRoute("/users/")({
  component: UsersPage,
  validateSearch: userSearchSchema, // Type-safe query params
  loaderDeps: ({ search }) => ({ search }), // Trigger loader on param change
  loader: async ({ deps: { search }, context }) => {
    // Fetch data using deps
    return fetchUsers(search);
  },
});

// 3. Component
function UsersPage() {
  // Type-safe access to loader data
  const users = Route.useLoaderData();
  // Type-safe access to search params
  const { page, sort } = Route.useSearch();

  return (
    <div>
      <h1>Users</h1>
      {/* ... */}
    </div>
  );
}
```

## Navigation

### The `Link` Component

Always use the `Link` component for internal navigation to ensure type safety.

```tsx
import { Link } from '@tanstack/react-router'

// Correct usage (Typescript will error if path doesn't exist)
<Link to="/users" search={{ page: 1, sort: 'asc' }}>
  Go to Users
</Link>

// Active states
<Link
  to="/dashboard"
  activeProps={{ className: 'font-bold text-primary' }}
  activeOptions={{ exact: true }}
>
  Dashboard
</Link>
```

### Imperative Navigation

Use the `useNavigate` hook for programmatic navigation (e.g., after form submission).

```tsx
const navigate = useNavigate();

function onSubmit() {
  navigate({ to: "/success", search: { id: "123" } });
}
```

## Data Loading Best Practices

- **Parallel Loading**: Loaders run in parallel.
- **Stale-While-Revalidate**: Integrate with TanStack Query for caching.

```tsx
// Integration with TanStack Query
export const Route = createFileRoute("/posts/$postId")({
  loader: ({ context: { queryClient }, params: { postId } }) => {
    return queryClient.ensureQueryData(postQueryOptions(postId));
  },
  component: PostComponent,
});
```

## Error Handling

Use `errorComponent` and `notFoundComponent` in your route configuration to handle edge cases gracefully.

```tsx
export const Route = createFileRoute("/dashboard")({
  component: Dashboard,
  errorComponent: ({ error }) => <ErrorPage error={error} />,
  notFoundComponent: () => <NotFound />,
});
```
