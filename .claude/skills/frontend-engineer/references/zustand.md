# Zustand State Management

## Overview

Zustand is our preferred global state management library due to its simplicity, minimal boilerplate, and hook-based API.

## Best Practices

### 1. Store Structure

Create separate stores for distinct features rather than one giant global store.
Examples: `useAuthStore`, `useUIStore`, `useCartStore`.

### 2. TypeScript Definition

Pattern: Define `State` and `Actions` separately, then merge them.

```tsx
import { create } from "zustand";

interface CounterState {
  count: number;
  isLoading: boolean;
}

interface CounterActions {
  increment: () => void;
  decrement: () => void;
  setCount: (value: number) => void;
  reset: () => void;
}

// Combine for the store type
type CounterStore = CounterState & CounterActions;

export const useCounterStore = create<CounterStore>((set) => ({
  // Initial State
  count: 0,
  isLoading: false,

  // Actions
  increment: () => set((state) => ({ count: state.count + 1 })),
  decrement: () => set((state) => ({ count: state.count - 1 })),
  setCount: (value) => set({ count: value }),
  reset: () => set({ count: 0 }),
}));
```

### 3. Async Actions

Zustand handles async actions natively. Just make the function async.

```tsx
interface AuthActions {
  login: (creds: Credentials) => Promise<void>;
}

// ... inside create
login: async (creds) => {
  set({ isLoading: true, error: null });
  try {
    const user = await apiLogin(creds);
    set({ user, isAuthenticated: true });
  } catch (e) {
    set({ error: "Login failed" });
  } finally {
    set({ isLoading: false });
  }
};
```

### 4. Selectors (Performance)

Always select only the state you need to prevent unnecessary re-renders.

```tsx
// ❌ Bad: Causes re-render on *any* store change
const { count, increment } = useCounterStore();

// ✅ Good: Only re-renders when specific properties change
const count = useCounterStore((state) => state.count);
const increment = useCounterStore((state) => state.increment);

// ✅ Good: Selecting multiple values (shallow comparison)
import { useShallow } from "zustand/react/shallow";

const { count, increment } = useCounterStore(
  useShallow((state) => ({
    count: state.count,
    increment: state.increment,
  })),
);
```

## Middleware

### Persist

Use `persist` to save state to `localStorage` or `sessionStorage`.

```tsx
import { persist, createJSONStorage } from "zustand/middleware";

export const useThemeStore = create<ThemeStore>()(
  persist(
    (set) => ({
      mode: "light",
      toggle: () =>
        set((state) => ({ mode: state.mode === "light" ? "dark" : "light" })),
    }),
    {
      name: "theme-storage", // unique name
      storage: createJSONStorage(() => localStorage),
    },
  ),
);
```

### DevTools

Connect to Redux DevTools extension for debugging.

```tsx
import { devtools } from 'zustand/middleware'

export const useStore = create<Store>()(
    devtools(
        (set) => ({ ... }),
        { name: 'MyStore' }
    )
)
```

## When to use Context vs Zustand?

- **Context**: For static or low-frequency updates (Theme, Localization) or dependency injection.
- **Zustand**: For high-frequency updates, complex state logic, or when avoiding prop drilling where performance matters.
