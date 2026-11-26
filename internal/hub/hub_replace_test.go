package hub

import "testing"

// AddReplacing says whether a live connection of the same agent was displaced,
// and closes the displaced one; Add keeps working as before.
func TestAddReplacingReportsTheDisplacedConnection(t *testing.T) {
	h := New()
	closed := 0
	_, replaced := h.AddReplacing("a", func() { closed++ })
	if replaced {
		t.Fatal("the first connection reported a replacement")
	}
	ch2, replaced := h.AddReplacing("a", func() {})
	if !replaced || closed != 1 {
		t.Fatalf("second connection: replaced=%v closed=%d, want true and 1", replaced, closed)
	}
	if !h.Remove("a", ch2) {
		t.Fatal("the current connection could not be removed")
	}
	if _, replaced := h.AddReplacing("a", nil); replaced {
		t.Fatal("a connection after removal reported a replacement")
	}
	if ch := h.Add("b", nil); ch == nil {
		t.Fatal("Add returned no channel")
	}
}
