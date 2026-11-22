package model

import (
	"errors"
	"slices"
	"testing"
)

func TestExitChain(t *testing.T) {
	byID := map[int64]Exit{
		1: {ID: 1, NextID: 2}, 2: {ID: 2, NextID: 3}, 3: {ID: 3},
		7: {ID: 7, NextID: 8}, 8: {ID: 8, NextID: 7},
		9:  {ID: 9, NextID: 42},
		10: {ID: 10, NextID: 11}, 11: {ID: 11, NextID: 12}, 12: {ID: 12, NextID: 13}, 13: {ID: 13, NextID: 14}, 14: {ID: 14},
	}
	ids := func(c []Exit) []int64 {
		var out []int64
		for _, e := range c {
			out = append(out, e.ID)
		}
		return out
	}
	if c, err := ExitChain(byID, 1); err != nil || !slices.Equal(ids(c), []int64{1, 2, 3}) {
		t.Fatalf("chain from 1 = %v, %v; want 1 2 3", ids(c), err)
	}
	if c, err := ExitChain(byID, 0); err != nil || len(c) != 0 {
		t.Fatalf("chain from 0 = %v, %v; want empty", c, err)
	}
	if c, err := ExitChain(byID, 11); err != nil || len(c) != MaxExitHops {
		t.Fatalf("chain of exactly %d = %v, %v", MaxExitHops, ids(c), err)
	}
	var ce *ChainError
	for _, tc := range []struct {
		first int64
		want  ChainProblem
		at    int64
	}{{7, ChainLoop, 7}, {9, ChainMissing, 42}, {10, ChainTooLong, 10}, {99, ChainMissing, 99}} {
		_, err := ExitChain(byID, tc.first)
		if !errors.As(err, &ce) || ce.Problem != tc.want || ce.ExitID != tc.at {
			t.Errorf("chain from %d = %v, want %s at %d", tc.first, err, tc.want, tc.at)
		}
	}
}
