package consensus

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadStartupRepairPlanDefaults(t *testing.T) {
	path := writeStartupRepairPlan(t, `{
		"schemaVersion": 1,
		"name": "test repair",
		"triggerBlocks": [
			"30f4243e9a14e7c6f4c74f831794e7b6e2958c84225603db79ea14182a75fd49"
		],
		"targetDaa": 100000
	}`)

	plan, err := loadStartupRepairPlan(path)
	if err != nil {
		t.Fatalf("loadStartupRepairPlan: %v", err)
	}
	if !plan.enabled() {
		t.Fatalf("expected plan to default to enabled")
	}
	if !plan.requireTriggerBlock() {
		t.Fatalf("expected trigger to be required when triggerBlocks is set")
	}
	if !plan.markRemovedDisqualified() {
		t.Fatalf("expected removed blocks to default to disqualified")
	}
	if !plan.cleanupRemovedBlockData() {
		t.Fatalf("expected removed block data cleanup to default to enabled")
	}
	if !plan.cleanupAtomicAboveTarget() {
		t.Fatalf("expected Atomic state cleanup above target to default to enabled")
	}
	if plan.scanBodyDescendants() {
		t.Fatalf("expected body descendant scan to default to disabled")
	}
	if plan.targetDAA() == nil || *plan.targetDAA() != 100000 {
		t.Fatalf("unexpected target DAA: %v", plan.targetDAA())
	}
}

func TestLoadStartupRepairPlanAllowsBodyDescendantScan(t *testing.T) {
	path := writeStartupRepairPlan(t, `{
		"schemaVersion": 1,
		"targetDaa": 100000,
		"scanBodyDescendants": true
	}`)

	plan, err := loadStartupRepairPlan(path)
	if err != nil {
		t.Fatalf("loadStartupRepairPlan: %v", err)
	}
	if !plan.scanBodyDescendants() {
		t.Fatalf("expected body descendant scan to be enabled")
	}
}

func TestLoadStartupRepairPlanAllowsTargetBlockWithoutTrigger(t *testing.T) {
	path := writeStartupRepairPlan(t, `{
		"schemaVersion": 1,
		"targetBlockHash": "81a489fa0d0c581452d9020bd3d28fdb1a677e9d4fa940b01ccf24b7c5d0b467"
	}`)

	plan, err := loadStartupRepairPlan(path)
	if err != nil {
		t.Fatalf("loadStartupRepairPlan: %v", err)
	}
	if plan.requireTriggerBlock() {
		t.Fatalf("did not expect trigger to be required without triggerBlocks")
	}
}

func TestLoadStartupRepairPlanRejectsAmbiguousTarget(t *testing.T) {
	path := writeStartupRepairPlan(t, `{
		"schemaVersion": 1,
		"targetBlockHash": "81a489fa0d0c581452d9020bd3d28fdb1a677e9d4fa940b01ccf24b7c5d0b467",
		"targetDaa": 100000
	}`)

	if _, err := loadStartupRepairPlan(path); err == nil {
		t.Fatalf("expected ambiguous repair target to fail")
	}
}

func TestLoadStartupRepairPlanRejectsUnknownFields(t *testing.T) {
	path := writeStartupRepairPlan(t, `{
		"schemaVersion": 1,
		"targetDaa": 100000,
		"typoField": true
	}`)

	if _, err := loadStartupRepairPlan(path); err == nil {
		t.Fatalf("expected unknown JSON field to fail")
	}
}

func writeStartupRepairPlan(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "repair.json")
	err := os.WriteFile(path, []byte(contents), 0600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}
