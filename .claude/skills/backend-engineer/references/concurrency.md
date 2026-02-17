# Go Concurrency Patterns

Go's concurrency model is based on CSP (Communicating Sequential Processes). The core philosophy is: **"Do not communicate by sharing memory; instead, share memory by communicating."**

## 1. Context Usage

`context.Context` is the standard way to handle cancellation, deadlines, and request-scoped values across API boundaries and goroutines.

### Best Practices

- **Always pass Context as the first argument** to functions that perform I/O or long-running operations.
- **Never store Context in a struct**; pass it explicitly.
- **Respect cancellation**: Check `ctx.Done()` in long loops.

```go
func (s *Service) ProcessBatch(ctx context.Context, items []Item) error {
    for _, item := range items {
        // Check for cancellation before processing each item
        if err := ctx.Err(); err != nil {
            return err
        }

        if err := s.process(ctx, item); err != nil {
            return err
        }
    }
    return nil
}
```

## 2. Structured Concurrency with errgroup

Prefer `golang.org/x/sync/errgroup` over raw `sync.WaitGroup` when you need to propagate errors or cancel the entire group if one task fails.

```go
import "golang.org/x/sync/errgroup"

func (s *Service) FetchAllData(ctx context.Context, ids []string) ([]Data, error) {
    g, ctx := errgroup.WithContext(ctx)
    results := make([]Data, len(ids))

    for i, id := range ids {
        i, id := i, id // Capture loop variables
        g.Go(func() error {
            data, err := s.client.Fetch(ctx, id)
            if err != nil {
                return err // Cancels the context for other goroutines
            }
            results[i] = data
            return nil
        })
    }

    if err := g.Wait(); err != nil {
        return nil, err
    }
    return results, nil
}
```

## 3. Preventing Goroutine Leaks

**Every goroutine you start must have a defined way to stop.**

### Common Leaks

- Sending to a channel that no one is reading from.
- Waiting on a channel that will never send.
- Waiting on a lock that will never be released.

### Solution: Use Context or Done Channels

```go
func Worker(ctx context.Context, jobs <-chan Job) {
    for {
        select {
        case <-ctx.Done():
            return // Clean exit on cancellation
        case job, ok := <-jobs:
            if !ok {
                return // Clean exit on channel close
            }
            process(job)
        }
    }
}
```

## 4. Worker Pools

Limit concurrency to avoid overwhelming resources (DB connections, memory, external APIs).

```go
func StartWorkerPool(ctx context.Context, numWorkers int, jobs <-chan Job, results chan<- Result) {
    var wg sync.WaitGroup
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for job := range jobs {
                // Respect context cancellation while processing
                if ctx.Err() != nil {
                    return
                }
                results <- process(job)
            }
        }()
    }
    wg.Wait()
}
```

## 5. Race Detection

Always run tests with the race detector enabled to catch data races.

```bash
go test -race ./...
```

A data race occurs when two goroutines access the same variable concurrently, and at least one of the accesses is a write.

**Fix**: Use `sync.Mutex`, `sync.RWMutex`, or channels to synchronize access.

```go
type SafeCounter struct {
    mu    sync.Mutex
    value int
}

func (c *SafeCounter) Inc() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.value++
}
```
