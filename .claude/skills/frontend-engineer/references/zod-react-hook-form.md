# Zod & React Hook Form Reference

## Overview

We use **React Hook Form** for form state management and **Zod** for schema validation. This combination provides a robust, type-safe, and performant form handling solution.

## Standard Pattern

### 1. Define the Schema

Define the shape of your form data using Zod.

```tsx
import { z } from "zod";

const loginSchema = z.object({
  email: z.string().email("Please enter a valid email"),
  password: z.string().min(8, "Password must be at least 8 characters"),
  rememberMe: z.boolean().default(false),
});

// Infer the TypeScript type from the schema
type LoginFormValues = z.infer<typeof loginSchema>;
```

### 2. Create the Form Hook

Use `useForm` with the `zodResolver`.

```tsx
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

export function LoginForm() {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: "",
      password: "",
      rememberMe: false,
    },
  });

  const onSubmit = async (data: LoginFormValues) => {
    // data is fully typed here
    await login(data);
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      {/* Fields */}
    </form>
  );
}
```

### 3. Controlled Components

For UI libraries (like Radix or custom inputs) that don't expose a simple `ref`, use `Controller`.

```tsx
import { Controller } from "react-hook-form";
import { Select } from "./ui/select"; // Example component

// Inside the component...
<Controller
  control={control}
  name="role"
  render={({ field }) => (
    <Select value={field.value} onValueChange={field.onChange}>
      {/* ...Options */}
    </Select>
  )}
/>;
```

## Form Component Guidelines

### Input Wrapper

Create reusable input wrappers to handle labels and error messages consistently.

```tsx
interface FormFieldProps {
  label: string;
  error?: string;
  children: React.ReactNode;
}

function FormField({ label, error, children }: FormFieldProps) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-sm font-medium text-slate-700">{label}</label>
      {children}
      {error && <span className="text-xs text-red-500">{error}</span>}
    </div>
  );
}

// Usage
<FormField label="Email" error={errors.email?.message}>
  <input {...register("email")} className="..." />
</FormField>;
```

## Common Zod Patterns

### Async Validation

```tsx
const schema = z.object({
  username: z.string().refine(async (val) => {
    const isAvailable = await checkUsername(val);
    return isAvailable;
  }, "Username is already taken"),
});
```

### Password Confirmation

```tsx
const signupSchema = z
  .object({
    password: z.string(),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  });
```

### Transformations

```tsx
const searchSchema = z.object({
  // Convert string input to number, handling empty strings
  age: z.string().transform((val) => (val === "" ? undefined : Number(val))),
});
```
