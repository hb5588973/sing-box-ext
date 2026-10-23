/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 041 — unit tests for the give-up rebind mechanics on top of the
 * self-heal harness (lx_giveup_selfheal_test.go): fresh vs pinned port,
 * debounce, and disabled = upstream parity. These use the post-fix API
 * (SetGiveUpRebind) and are NOT expected to compile on the pre-fix base.
 */

package device

import (
	"testing"
	"time"
)

func waitOpens(t *testing.T, bind *gateBind, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for bind.openCount() < want {
		if time.Now().After(deadline) {
			t.Fatalf("bind reopened %d times, want %d", bind.openCount(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Fresh mode (listen_port not pinned): the rebind must ask the OS for a new
// ephemeral port — Open is called with port 0.
func TestGiveUpRebindFreshPort(t *testing.T) {
	pair := newGiveUpPair(t, false)
	pair.devA.SetGiveUpRebind(true, true)

	triggerGiveUp(t, pair.devA, pair.pkB)
	waitOpens(t, pair.bindA, 2)

	ports := pair.bindA.portsSnapshot()
	if ports[1] != 0 {
		t.Fatalf("rebind requested port %d, want 0 (fresh ephemeral)", ports[1])
	}
}

// Pinned mode (explicit listen_port): the rebind must keep the current port.
// chanBind.Open reports its source id (1) as the actual port, so the device
// stores net.port=1 after the first Open and must reuse it.
func TestGiveUpRebindPinnedPortPreserved(t *testing.T) {
	pair := newGiveUpPair(t, false)
	pair.devA.SetGiveUpRebind(true, false)

	triggerGiveUp(t, pair.devA, pair.pkB)
	waitOpens(t, pair.bindA, 2)

	ports := pair.bindA.portsSnapshot()
	if ports[1] != 1 {
		t.Fatalf("rebind requested port %d, want 1 (pinned)", ports[1])
	}
}

// A second give-up inside the debounce window must not rebind again.
func TestGiveUpRebindDebounce(t *testing.T) {
	pair := newGiveUpPair(t, false)

	triggerGiveUp(t, pair.devA, pair.pkB)
	waitOpens(t, pair.bindA, 2)

	triggerGiveUp(t, pair.devA, pair.pkB)
	time.Sleep(300 * time.Millisecond)
	if got := pair.bindA.openCount(); got != 2 {
		t.Fatalf("debounce failed: bind opened %d times, want 2", got)
	}
}

// Disabled: the give-up branch must behave exactly like upstream — flush and
// stop, no rebind.
func TestGiveUpRebindDisabled(t *testing.T) {
	pair := newGiveUpPair(t, false)
	pair.devA.SetGiveUpRebind(false, false)

	triggerGiveUp(t, pair.devA, pair.pkB)
	time.Sleep(300 * time.Millisecond)
	if got := pair.bindA.openCount(); got != 1 {
		t.Fatalf("disabled mechanism still rebound: %d opens, want 1", got)
	}
}
