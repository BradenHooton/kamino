package models

import (
	"time"

	"github.com/google/uuid"
)

// MFA Recovery Status Constants
const (
	MFARecoveryStatusPending   = "pending"
	MFARecoveryStatusConfirmed = "confirmed"
	MFARecoveryStatusExecuted  = "executed"
	MFARecoveryStatusExpired   = "expired"
	MFARecoveryStatusCancelled = "cancelled"
)

// MFARecoveryRequest represents an MFA recovery request
type MFARecoveryRequest struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	InitiatorAdminID uuid.UUID
	ConfirmerAdminID *uuid.UUID
	Reason           string
	Status           string
	CreatedAt        time.Time
	ConfirmedAt      *time.Time
	ExpiresAt        time.Time
	ExecutedAt       *time.Time
}

// IsExpired checks if the recovery request has expired
func (r *MFARecoveryRequest) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// IsPending checks if the recovery request is awaiting confirmation
func (r *MFARecoveryRequest) IsPending() bool {
	return r.Status == MFARecoveryStatusPending
}

// IsConfirmed checks if the recovery request has been confirmed by a second admin
func (r *MFARecoveryRequest) IsConfirmed() bool {
	return r.Status == MFARecoveryStatusConfirmed
}

// CanBeConfirmedBy validates the four-eyes principle
// Returns true if the confirmer is different from the initiator
func (r *MFARecoveryRequest) CanBeConfirmedBy(confirmerAdminID uuid.UUID) bool {
	return r.Status == MFARecoveryStatusPending &&
		!r.IsExpired() &&
		confirmerAdminID != r.InitiatorAdminID
}
