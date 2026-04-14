package coinbasemanager

import (
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/dagconfig"
)

func TestCalcDeflationaryPeriodBlockSubsidy(t *testing.T) {
	const secondsPerMonth = 2629800
	const secondsPerDay = 86400
	const deflationaryPhaseDaaScore = secondsPerDay * 1
	deflationaryPhaseBaseSubsidy := dagconfig.MainnetParams.DeflationaryPhaseBaseSubsidy
	coinbaseManagerInterface := New(
		nil,
		0,
		0,
		0,
		&externalapi.DomainHash{},
		deflationaryPhaseDaaScore,
		deflationaryPhaseBaseSubsidy,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil)
	coinbaseManagerInstance := coinbaseManagerInterface.(*coinbaseManager)

	tests := []struct {
		name                 string
		blockDaaScore        uint64
		expectedBlockSubsidy uint64
	}{
		{
			name:                 "start of deflationary phase",
			blockDaaScore:        deflationaryPhaseDaaScore,
			expectedBlockSubsidy: subsidyByDeflationaryMonthTable[0],
		},
		{
			name:                 "just before month boundary",
			blockDaaScore:        deflationaryPhaseDaaScore + secondsPerMonth - 1,
			expectedBlockSubsidy: subsidyByDeflationaryMonthTable[0],
		},
		{
			name:                 "after one month",
			blockDaaScore:        deflationaryPhaseDaaScore + secondsPerMonth,
			expectedBlockSubsidy: subsidyByDeflationaryMonthTable[1],
		},
		{
			name:                 "after one year",
			blockDaaScore:        deflationaryPhaseDaaScore + secondsPerMonth*12,
			expectedBlockSubsidy: subsidyByDeflationaryMonthTable[12],
		},
		{
			name:                 "late in deflationary schedule",
			blockDaaScore:        deflationaryPhaseDaaScore + secondsPerMonth*(uint64(len(subsidyByDeflationaryMonthTable))-2),
			expectedBlockSubsidy: subsidyByDeflationaryMonthTable[len(subsidyByDeflationaryMonthTable)-2],
		},
		{
			name:                 "after subsidy table depletion",
			blockDaaScore:        deflationaryPhaseDaaScore + secondsPerMonth*(uint64(len(subsidyByDeflationaryMonthTable))+100),
			expectedBlockSubsidy: subsidyByDeflationaryMonthTable[len(subsidyByDeflationaryMonthTable)-1],
		},
	}

	for _, test := range tests {
		blockSubsidy := coinbaseManagerInstance.calcDeflationaryPeriodBlockSubsidy(test.blockDaaScore)
		if blockSubsidy != test.expectedBlockSubsidy {
			t.Errorf("TestCalcDeflationaryPeriodBlockSubsidy: test '%s' failed. Want: %d, got: %d",
				test.name, test.expectedBlockSubsidy, blockSubsidy)
		}
	}
}

func TestBuildSubsidyTable(t *testing.T) {
	deflationaryPhaseBaseSubsidy := dagconfig.MainnetParams.DeflationaryPhaseBaseSubsidy
	coinbaseManagerInterface := New(
		nil,
		0,
		0,
		0,
		&externalapi.DomainHash{},
		0,
		deflationaryPhaseBaseSubsidy,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil)
	coinbaseManagerInstance := coinbaseManagerInterface.(*coinbaseManager)

	if len(subsidyByDeflationaryMonthTable) == 0 {
		t.Fatalf("subsidyByDeflationaryMonthTable must not be empty")
	}

	if subsidyByDeflationaryMonthTable[0] != deflationaryPhaseBaseSubsidy {
		t.Fatalf("first table entry mismatch: expected %d got %d",
			deflationaryPhaseBaseSubsidy, subsidyByDeflationaryMonthTable[0])
	}

	for i := 1; i < len(subsidyByDeflationaryMonthTable); i++ {
		if subsidyByDeflationaryMonthTable[i] > subsidyByDeflationaryMonthTable[i-1] {
			t.Fatalf("table must be non-increasing at month %d: %d > %d",
				i, subsidyByDeflationaryMonthTable[i], subsidyByDeflationaryMonthTable[i-1])
		}
	}

	if subsidyByDeflationaryMonthTable[len(subsidyByDeflationaryMonthTable)-1] != 0 {
		t.Fatalf("last table entry must be zero, got %d",
			subsidyByDeflationaryMonthTable[len(subsidyByDeflationaryMonthTable)-1])
	}

	for month, tableSubsidy := range subsidyByDeflationaryMonthTable {
		floatSubsidy := coinbaseManagerInstance.calcDeflationaryPeriodBlockSubsidyFloatCalc(uint64(month))
		var diff uint64
		if tableSubsidy >= floatSubsidy {
			diff = tableSubsidy - floatSubsidy
		} else {
			diff = floatSubsidy - tableSubsidy
		}
		if diff > 1 {
			t.Fatalf("table diverges from float calc by more than 1 sompi at month %d: table=%d float=%d",
				month, tableSubsidy, floatSubsidy)
		}
	}
}
