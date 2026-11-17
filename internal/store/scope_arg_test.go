package store

import (
	"testing"

	"github.com/google/uuid"
)

// scopeArg is the $n every scoped query compares with user_scopes.user_id, a
// uuid column. An unrestricted principal (an administrator, the admin token)
// has no scope user, and must be sent as SQL NULL: an empty string fails the
// whole statement at bind time, before any `NOT scoped` branch can skip the
// scope check. That is how Alerts > Silences & maintenance answered 500 to
// every administrator.
func TestScopeArgSendsNullForUnscopedPrincipals(t *testing.T) {
	if got := scopeArg(""); got != nil {
		t.Fatalf("scopeArg(\"\") = %#v, want nil (SQL NULL)", got)
	}
	id := uuid.NewString()
	if got := scopeArg(id); got != id {
		t.Fatalf("scopeArg(%q) = %#v, want the user id unchanged", id, got)
	}
}
