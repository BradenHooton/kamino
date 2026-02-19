package auth_test

import (
	"testing"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestTimingDelay_Wait_OnFailure(t *testing.T) {
	config := auth.TimingConfig{
		BaseDelayMs:    100,
		RandomDelayMs:  50,
		DelayOnSuccess: false,
	}

	timing := auth.NewTimingDelay(config)
	startTime := time.Now()

	timing.Wait(false)

	elapsed := time.Since(startTime)
	// Should be at least 100ms (base) but less than 150ms (base + max random)
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
	assert.Less(t, elapsed, 200*time.Millisecond) // Reasonable upper bound
}

func TestTimingDelay_Wait_OnSuccess_NoDelay(t *testing.T) {
	config := auth.TimingConfig{
		BaseDelayMs:    100,
		RandomDelayMs:  50,
		DelayOnSuccess: false,
	}

	timing := auth.NewTimingDelay(config)
	startTime := time.Now()

	timing.Wait(true)

	elapsed := time.Since(startTime)
	// Should be minimal when success and DelayOnSuccess=false
	assert.Less(t, elapsed, 10*time.Millisecond)
}

func TestTimingDelay_Wait_OnSuccess_WithDelay(t *testing.T) {
	config := auth.TimingConfig{
		BaseDelayMs:    100,
		RandomDelayMs:  50,
		DelayOnSuccess: true,
	}

	timing := auth.NewTimingDelay(config)
	startTime := time.Now()

	timing.Wait(true)

	elapsed := time.Since(startTime)
	// Should still delay even on success
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
}

func TestTimingDelay_WaitFrom_AdjustsForElapsedTime(t *testing.T) {
	config := auth.TimingConfig{
		BaseDelayMs:    100,
		RandomDelayMs:  0, // No random for predictable test
		DelayOnSuccess: false,
	}

	timing := auth.NewTimingDelay(config)
	startTime := time.Now()

	// Simulate some work already done
	time.Sleep(50 * time.Millisecond)

	timing.WaitFrom(startTime, false)

	elapsed := time.Since(startTime)
	// Should total approximately 100ms (base), not 150ms
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
	assert.Less(t, elapsed, 120*time.Millisecond)
}

func TestTimingDelay_WaitFrom_NoWaitIfAlreadyExceeded(t *testing.T) {
	config := auth.TimingConfig{
		BaseDelayMs:    50,
		RandomDelayMs:  0,
		DelayOnSuccess: false,
	}

	timing := auth.NewTimingDelay(config)
	startTime := time.Now()

	// Simulate work that already exceeded target delay
	time.Sleep(100 * time.Millisecond)

	timing.WaitFrom(startTime, false)

	elapsed := time.Since(startTime)
	// Should not add more delay if already exceeded
	assert.Less(t, elapsed, 120*time.Millisecond)
}
