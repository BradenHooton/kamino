# Admin Panel Architecture & CRUD Patterns

Guidelines for building efficient, scalable admin panels for internal management.

## Layout & Navigation

- **Sidebar-First**: Persistent or collapsible sidebars for primary navigation.
- **Contextual Actions**: Place "Create," "Bulk Delete," and "Export" actions in a consistent header area.
- **Breadcrumbs**: Always show the user where they are in the hierarchy.

## Data Presentation

- **Data Tables**:
  - Implement sorting, filtering, and pagination.
  - Use "Select All" patterns for bulk operations.
  - Cell formatting: Dates, currency, and status badges should be standardized.
- **Empty States**: Never show an empty white screen; provide a "No results found" or "Get started" call to action.

## CRUD Workflows

- **Modals vs. Pages**:
  - Use Modals for simple, 1-3 field edits.
  - Use full routes for complex entities with many fields or sub-resources.
- **Form States**:
  - Always show loading indicators during submission.
  - Disable "Save" buttons during inflight requests.
  - Provide immediate success/error toast notifications.

## Role-Based Access Control (RBAC) UI

- **Conditional Rendering**: Hide buttons or entire routes based on user permissions.
- **Read-Only States**: If a user has "View" but not "Edit" permissions, show forms with disabled inputs and clear messaging.
- **Owner-Based Edits**: Restrict editing of specific records to their creators or admins.

## Best Practices

- **Standardized DTOs**: Ensure the admin panel uses the same data models as the rest of the app.
- **Audit Logs**: When possible, display "Last updated by..." or change history for critical records.
- **Developer Experience**: Use a unified `AdminLayout` component to ensure consistency across all admin pages.
