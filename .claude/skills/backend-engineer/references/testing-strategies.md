# Go Testing Strategies

High-quality Go tests are deterministic, fast, and easy to debug.

## 1. Table-Driven Tests

Table-driven tests are the idiomatic way to write unit tests in Go. They clearly separate test data from test logic.

```go
func TestAdd(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"positive numbers", 2, 3, 5},
        {"negative numbers", -1, -2, -3},
        {"mixed", -1, 1, 0},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("Add(%d, %d) = %d; want %d", tt.a, tt.b, result, tt.expected)
            }
        })
    }
}
```

## 2. Assertions with Testify

Use `github.com/stretchr/testify/assert` and `require` for more readable assertions.

- Use **assert** when you want the test to continue after failure.
- Use **require** when the test cannot verify anything else if this check fails (e.g., error checking, nil checks).

```go
import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestSomething(t *testing.T) {
    val, err := DoSomething()
    require.NoError(t, err) // Stop test if error
    assert.Equal(t, "expected", val)
}
```

## 3. Mocking Dependencies

Define small interfaces for your dependencies (see [Implementation Patterns](implementation-patterns.md)). This allows you to generate mocks easily.

Use `github.com/stretchr/testify/mock`.

```go
// Generate mock (using mockery or manually)
type MockUserRepo struct {
    mock.Mock
}

func (m *MockUserRepo) GetUser(ctx context.Context, id string) (*User, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*User), args.Error(1)
}

// In test
func TestService_GetUser(t *testing.T) {
    mockRepo := new(MockUserRepo)
    service := NewService(mockRepo)

    mockRepo.On("GetUser", mock.Anything, "123").Return(&User{ID: "123"}, nil)

    user, err := service.GetUser(context.Background(), "123")
    require.NoError(t, err)
    assert.Equal(t, "123", user.ID)

    mockRepo.AssertExpectations(t)
}
```

## 4. Integration Testing with Testcontainers

For database interactions, avoid mocking the database driver. Instead, spin up a real Postgres instance using `testcontainers-go`.

```go
func TestRepository_CreateUser(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // helper function to start container
    ctx := context.Background()
    container, dbURL := StartPostgresContainer(ctx)
    defer container.Terminate(ctx)

    dbPool := ConnectDB(dbURL)
    defer dbPool.Close()

    repo := NewRepository(dbPool)

    // Run test against real DB
    err := repo.CreateUser(ctx, User{Name: "Test"})
    require.NoError(t, err)
}
```

## 5. HTTP Handler Testing

Use `net/http/httptest` to test your handlers without starting a full server.

```go
func TestHandler_Get(t *testing.T) {
    req := httptest.NewRequest(http.MethodGet, "/users", nil)
    w := httptest.NewRecorder()

    MyHandler(w, req)

    res := w.Result()
    defer res.Body.Close()

    require.Equal(t, http.StatusOK, res.StatusCode)

    var data map[string]interface{}
    json.NewDecoder(res.Body).Decode(&data)
    assert.Contains(t, data, "key")
}
```
