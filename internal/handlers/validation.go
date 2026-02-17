package handlers

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

// ValidationErrorResponse represents a validation error with field-level details
type ValidationErrorResponse struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Global validator instance (reused across all handlers)
var validate = validator.New()

// ValidateRequest validates a request struct using go-playground/validator
// Returns a user-friendly error message if validation fails
func ValidateRequest(req interface{}) error {
	if err := validate.Struct(req); err != nil {
		// Extract validation errors and format them
		if ve, ok := err.(validator.ValidationErrors); ok {
			var errors []ValidationErrorResponse
			for _, fieldError := range ve {
				errors = append(errors, ValidationErrorResponse{
					Field:   fieldError.Field(),
					Message: formatValidationError(fieldError),
				})
			}
			// Return first error for simple handling (can be extended for multiple errors)
			if len(errors) > 0 {
				return fmt.Errorf("validation failed: %s: %s",
					errors[0].Field,
					errors[0].Message)
			}
		}
		return fmt.Errorf("validation failed: %w", err)
	}
	return nil
}

// formatValidationError converts a validator FieldError to a user-friendly message
func formatValidationError(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "this field is required"
	case "email":
		return "must be a valid email address"
	case "min":
		return fmt.Sprintf("must have a minimum of %s characters", fe.Param())
	case "max":
		return fmt.Sprintf("must have a maximum of %s characters", fe.Param())
	case "oneof":
		return fmt.Sprintf("must be one of: %s", fe.Param())
	case "gte":
		return fmt.Sprintf("must be greater than or equal to %s", fe.Param())
	case "lte":
		return fmt.Sprintf("must be less than or equal to %s", fe.Param())
	default:
		return fmt.Sprintf("failed validation: %s", fe.Tag())
	}
}
