package netfilter

import (
	"context"
	"slices"
	"testing"

	"github.com/egorlepa/netshunt/internal/platform/runnertest"
)

func TestEnsureTableCreatesWithMaxElem(t *testing.T) {
	run := runnertest.New()
	run.On("ipset list -t bypass", "", runnertest.ErrScripted)
	s := &IPSet{Name: "bypass", Runner: run}
	if err := s.EnsureTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"ipset list -t bypass", "ipset create bypass hash:net hashsize 16384 maxelem 262144"}
	if got := run.Calls(); !slices.Equal(got, want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
}

func TestEnsureTableExistingIsReadOnly(t *testing.T) {
	run := runnertest.New()
	run.On("ipset list -t bypass", "Name: bypass", nil)
	s := &IPSet{Name: "bypass", Runner: run}
	if err := s.EnsureTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := run.Calls(); !slices.Equal(got, []string{"ipset list -t bypass"}) {
		t.Fatalf("calls = %v", got)
	}
}

func TestListParsesMembers(t *testing.T) {
	run := runnertest.New()
	run.On("ipset list bypass -output plain", "Name: bypass\nType: hash:net\nHeader: family inet hashsize 1024 maxelem 262144\nMembers:\n1.2.3.4\n10.0.0.0/8\n", nil)
	got, err := (&IPSet{Name: "bypass", Runner: run}).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"1.2.3.4", "10.0.0.0/8"}) {
		t.Fatalf("List = %v", got)
	}
}

func TestAddBatchUsesRestoreStdin(t *testing.T) {
	run := runnertest.New()
	s := &IPSet{Name: "bypass", Runner: run}
	if err := s.AddBatch(context.Background(), []string{"1.2.3.4", "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DelBatch(context.Background(), []string{"5.6.7.8"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddBatch(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{"ipset restore -! <<stdin", "ipset restore -! <<stdin"}
	if got := run.Calls(); !slices.Equal(got, wantCalls) {
		t.Fatalf("calls = %v, want %v", got, wantCalls)
	}
	wantIn := []string{"add bypass 1.2.3.4\nadd bypass 10.0.0.0/8\n", "del bypass 5.6.7.8\n"}
	if got := run.Inputs(); !slices.Equal(got, wantIn) {
		t.Fatalf("inputs = %q, want %q", got, wantIn)
	}
}
