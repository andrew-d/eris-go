// Package result contains a generic type that represents either a value or an
// error.
package result

type Result[V any] struct {
	v   V // valid if err is nil
	err error
}

// Of creates a new Result with a value.
func Of[V any](v V) Result[V] {
	return Result[V]{v: v}
}

// Error creates a new Result with an error.
func Error[V any](err error) Result[V] {
	return Result[V]{err: err}
}

// Value returns r's result value and error. If r is an error, Value returns
// the zero value of V.
func (r Result[V]) Value() (V, error) {
	return r.v, r.err
}

// MustValue returns r's result value and panics if r is an error.
func (r Result[V]) MustValue() V {
	if r.err != nil {
		panic(r.err)
	}
	return r.v
}

// Err returns r's error if it is an error, nil otherwise.
func (r Result[V]) Err() error {
	return r.err
}
