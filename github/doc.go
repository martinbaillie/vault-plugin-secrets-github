// Package github manages the configuration and execution of the Vault Secrets Plugin for GitHub.
package github

// Error is a simple immutable sentinel error implementation.
type Error string

// Error is the marker interface for an error.
func (e Error) Error() string {
	return string(e)
}
