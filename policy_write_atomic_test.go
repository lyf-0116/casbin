// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package casbin

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/casbin/casbin/v3/log"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

type policyWriteCall struct {
	sec   string
	ptype string
	rule  []string
}

type atomicWriteAdapter struct {
	addErr    error
	removeErr error
	degraded  bool

	addCalls    []policyWriteCall
	removeCalls []policyWriteCall
	onAdd       func()
}

func (a *atomicWriteAdapter) LoadPolicy(model.Model) error { return nil }
func (a *atomicWriteAdapter) SavePolicy(model.Model) error { return nil }

func (a *atomicWriteAdapter) AddPolicy(sec, ptype string, rule []string) error {
	a.addCalls = append(a.addCalls, policyWriteCall{sec: sec, ptype: ptype, rule: append([]string(nil), rule...)})
	if a.onAdd != nil {
		a.onAdd()
	}
	return a.addErr
}

func (a *atomicWriteAdapter) RemovePolicy(sec, ptype string, rule []string) error {
	a.removeCalls = append(a.removeCalls, policyWriteCall{sec: sec, ptype: ptype, rule: append([]string(nil), rule...)})
	return a.removeErr
}

func (a *atomicWriteAdapter) RemoveFilteredPolicy(string, string, int, ...string) error {
	return nil
}

func (a *atomicWriteAdapter) AllowDegradedPolicyWrites() bool { return a.degraded }

type atomicTransactionAdapter struct {
	*atomicWriteAdapter
	beginCalls    int
	commitCalls   int
	rollbackCalls int
	txAddErr      error
	txOnAdd       func()
	txStorage     *atomicWriteAdapter
}

type atomicTransactionContext struct {
	adapter *atomicTransactionAdapter
}

func (a *atomicTransactionAdapter) BeginTransaction(context.Context) (persist.TransactionContext, error) {
	a.beginCalls++
	a.txStorage = &atomicWriteAdapter{addErr: a.txAddErr, onAdd: a.txOnAdd}
	return &atomicTransactionContext{adapter: a}, nil
}

func (tx *atomicTransactionContext) Commit() error {
	tx.adapter.commitCalls++
	return nil
}

func (tx *atomicTransactionContext) Rollback() error {
	tx.adapter.rollbackCalls++
	return nil
}

func (tx *atomicTransactionContext) GetAdapter() persist.Adapter {
	return tx.adapter.txStorage
}

func TestAtomicAddPolicyRejectsRewordedNotImplementedByValue(t *testing.T) {
	adapter := &atomicWriteAdapter{
		addErr: fmt.Errorf("adapter v2 says unsupported: %w", persist.ErrNotImplemented),
	}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	added, err := e.AddPolicy("alice", "data1", "read")
	if added {
		t.Fatal("AddPolicy should not report the rule as added")
	}
	if !stderrors.Is(err, persist.ErrNotImplemented) {
		t.Fatalf("expected not-implemented sentinel by value, got %v", err)
	}
	if len(adapter.addCalls) != 1 {
		t.Fatalf("expected one storage add attempt, got %d", len(adapter.addCalls))
	}
	if ok, err := e.HasPolicy("alice", "data1", "read"); err != nil || ok {
		t.Fatalf("read-only adapter failure must not leave an in-memory rule: ok=%v err=%v", ok, err)
	}
}

func TestAtomicAddPolicyDoesNotRecognizeLegacyTextAlone(t *testing.T) {
	adapter := &atomicWriteAdapter{addErr: stderrors.New("not implemented")}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	_, err = e.AddPolicy("alice", "data1", "read")
	if err == nil {
		t.Fatal("legacy error text without the sentinel should fail closed")
	}
	if stderrors.Is(err, persist.ErrNotImplemented) {
		t.Fatal("a bare string error must not satisfy value comparison")
	}
}

func TestAtomicAddPolicyExplicitDegradationWarns(t *testing.T) {
	adapter := &atomicWriteAdapter{
		degraded: true,
		addErr:   fmt.Errorf("renamed unsupported error: %w", persist.ErrNotImplemented),
	}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	var entries []*log.LogEntry
	logger := log.NewDefaultLogger()
	if err := logger.SetLogCallback(func(entry *log.LogEntry) error {
		entries = append(entries, entry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.SetLogger(logger)

	added, err := e.AddPolicy("alice", "data1", "read")
	if err != nil || !added {
		t.Fatalf("explicit degradation should preserve memory write: added=%v err=%v", added, err)
	}
	if ok, _ := e.HasPolicy("alice", "data1", "read"); !ok {
		t.Fatal("degraded write should remain visible in memory")
	}

	var warnings []error
	for _, entry := range entries {
		warnings = append(warnings, entry.Warnings...)
	}
	if len(warnings) != 1 || !stderrors.Is(warnings[0], persist.ErrDegradedPolicyWrite) {
		t.Fatalf("expected one degradation audit warning, got %#v", warnings)
	}
}

func TestAtomicAddPolicyRejectsMalformedRuleBeforeStorage(t *testing.T) {
	adapter := &atomicWriteAdapter{}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	added, err := e.AddPolicy("only-one-field")
	if err == nil || added {
		t.Fatalf("malformed rule should fail before persistence: added=%v err=%v", added, err)
	}
	if len(adapter.addCalls) != 0 {
		t.Fatalf("malformed rule reached storage: %+v", adapter.addCalls)
	}
	if ok, _ := e.HasPolicy("only-one-field"); ok {
		t.Fatal("malformed rule should not be in memory")
	}
}

func TestAtomicAddPolicyCompensatesStorageAfterMemoryFailure(t *testing.T) {
	adapter := &atomicWriteAdapter{}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}
	adapter.onAdd = func() { delete(e.model["p"], "p") }

	added, err := e.AddPolicy("alice", "data1", "read")
	if err == nil || added {
		t.Fatalf("memory failure should return an error and added=false: added=%v err=%v", added, err)
	}
	if len(adapter.removeCalls) != 1 {
		t.Fatalf("expected one compensating remove, got %d", len(adapter.removeCalls))
	}
	if call := adapter.removeCalls[0]; call.sec != "p" || call.ptype != "p" {
		t.Fatalf("unexpected policy section/type: %s/%s", call.sec, call.ptype)
	}
	got := adapter.removeCalls[0].rule
	if len(got) != 3 || got[0] != "alice" || got[1] != "data1" || got[2] != "read" {
		t.Fatalf("unexpected compensating rule: %#v", got)
	}
}

func TestAtomicAddPolicySurfacesFailedCompensation(t *testing.T) {
	memoryErr := stderrors.New("memory unavailable")
	adapter := &atomicWriteAdapter{removeErr: memoryErr}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}
	adapter.onAdd = func() { delete(e.model["p"], "p") }

	_, err = e.AddPolicy("alice", "data1", "read")
	if !stderrors.Is(err, persist.ErrPolicyRollbackFailed) {
		t.Fatalf("expected rollback sentinel in joined error, got %v", err)
	}
	if len(adapter.removeCalls) != 1 {
		t.Fatalf("expected compensation attempt, got %d calls", len(adapter.removeCalls))
	}
}

func TestAtomicAddPolicyCommitsTransaction(t *testing.T) {
	adapter := &atomicTransactionAdapter{atomicWriteAdapter: &atomicWriteAdapter{}}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	added, err := e.AddPolicy("alice", "data1", "read")
	if err != nil || !added {
		t.Fatalf("transactional add should succeed: added=%v err=%v", added, err)
	}
	if adapter.beginCalls != 1 || adapter.commitCalls != 1 || adapter.rollbackCalls != 0 {
		t.Fatalf("unexpected transaction calls: begin=%d commit=%d rollback=%d",
			adapter.beginCalls, adapter.commitCalls, adapter.rollbackCalls)
	}
	if adapter.txStorage == nil || len(adapter.txStorage.addCalls) != 1 {
		t.Fatalf("expected one add on the transaction adapter, got %#v", adapter.txStorage)
	}
	if ok, _ := e.HasPolicy("alice", "data1", "read"); !ok {
		t.Fatal("committed policy should be in memory")
	}
}

func TestAtomicAddPolicyRollsBackTransactionOnMemoryFailure(t *testing.T) {
	adapter := &atomicTransactionAdapter{atomicWriteAdapter: &atomicWriteAdapter{}}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}
	adapter.txOnAdd = func() { delete(e.model["p"], "p") }

	added, err := e.AddPolicy("alice", "data1", "read")
	if err == nil || added {
		t.Fatalf("memory failure should fail the add: added=%v err=%v", added, err)
	}
	if adapter.beginCalls != 1 || adapter.rollbackCalls != 1 || adapter.commitCalls != 0 {
		t.Fatalf("expected rollback without commit: begin=%d commit=%d rollback=%d",
			adapter.beginCalls, adapter.commitCalls, adapter.rollbackCalls)
	}
	if adapter.txStorage == nil || len(adapter.txStorage.addCalls) != 1 {
		t.Fatalf("expected one add on the transaction adapter, got %#v", adapter.txStorage)
	}
}

type atomicContextWriteAdapter struct {
	*atomicWriteAdapter
}

func (a *atomicContextWriteAdapter) LoadPolicyCtx(context.Context, model.Model) error {
	return nil
}

func (a *atomicContextWriteAdapter) SavePolicyCtx(context.Context, model.Model) error {
	return nil
}

func (a *atomicContextWriteAdapter) AddPolicyCtx(ctx context.Context, sec, ptype string, rule []string) error {
	return a.AddPolicy(sec, ptype, rule)
}

func (a *atomicContextWriteAdapter) RemovePolicyCtx(ctx context.Context, sec, ptype string, rule []string) error {
	return a.RemovePolicy(sec, ptype, rule)
}

func (a *atomicContextWriteAdapter) RemoveFilteredPolicyCtx(context.Context, string, string, int, ...string) error {
	return nil
}

func TestAtomicAddPolicyCtxCompensatesThroughContextAdapter(t *testing.T) {
	adapter := &atomicContextWriteAdapter{atomicWriteAdapter: &atomicWriteAdapter{}}
	enforcerIface, err := NewContextEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}
	e := enforcerIface.(*ContextEnforcer)
	adapter.onAdd = func() { delete(e.model["p"], "p") }

	added, err := e.AddPolicyCtx(context.Background(), "alice", "data1", "read")
	if err == nil || added {
		t.Fatalf("context memory failure should fail: added=%v err=%v", added, err)
	}
	if len(adapter.removeCalls) != 1 {
		t.Fatalf("expected one context compensation remove, got %d", len(adapter.removeCalls))
	}
}
