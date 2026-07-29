package model

import "testing"

func TestRiskExceeds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		risk Risk
		max  Risk
		want bool
	}{
		{name: "read within read", risk: RiskRead, max: RiskRead, want: false},
		{name: "write exceeds read", risk: RiskWrite, max: RiskRead, want: true},
		{name: "destroy exceeds write", risk: RiskDestroy, max: RiskWrite, want: true},
		{name: "read within destroy", risk: RiskRead, max: RiskDestroy, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.risk.Exceeds(tt.max); got != tt.want {
				t.Fatalf("Risk.Exceeds() = %v, want %v", got, tt.want)
			}
		})
	}
}
