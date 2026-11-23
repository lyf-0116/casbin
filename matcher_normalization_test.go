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
	"testing"

	"github.com/casbin/casbin/v3/model"
)

func newNormalizationEnforcer(t *testing.T, matcher string) *Enforcer {
	t.Helper()
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", matcher)

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	_, _ = e.AddPolicy("alice", "data1", "read")
	return e
}

// TestNormalizationBracketInRuntimeMatcher makes sure the square-bracket form of
// an "in" clause is accepted by runtime matchers, just like model-file matchers.
func TestNormalizationBracketInRuntimeMatcher(t *testing.T) {
	e := newNormalizationEnforcer(t, "r.sub == p.sub && r.obj in ['data2', 'data3']")

	got, err := e.EnforceWithMatcher(
		"r.sub == p.sub && r.obj in ['data2', 'data3'] # tail comment",
		"alice", "data2", "read")
	if err != nil {
		t.Fatalf("EnforceWithMatcher returned error: %v", err)
	}
	if !got {
		t.Errorf("expected match for r.obj in ['data2', 'data3']")
	}
}

// TestNormalizationBracketInManagementQuery makes sure the management-side policy
// preview query accepts the same bracket syntax as the enforcement path.
func TestNormalizationBracketInManagementQuery(t *testing.T) {
	e := newNormalizationEnforcer(t, "r.sub == p.sub")

	res, err := e.GetFilteredNamedPolicyWithMatcher("p", "p.obj in ['data1']")
	if err != nil {
		t.Fatalf("GetFilteredNamedPolicyWithMatcher returned error: %v", err)
	}
	if len(res) != 1 {
		t.Errorf("expected one matching policy, got %v", res)
	}
}

// TestNormalizationQuotedBracketsPreserved ensures brackets inside quoted
// literals are not rewritten when "in" clauses are normalized.
func TestNormalizationQuotedBracketsPreserved(t *testing.T) {
	matcher := "r.obj == 'x[0]' && r.sub == p.sub && r.act in ['read']"
	e := newNormalizationEnforcer(t, matcher)

	got, err := e.Enforce("alice", "x[0]", "read")
	if err != nil {
		t.Fatalf("model matcher returned error: %v", err)
	}
	if !got {
		t.Errorf("model matcher: expected quoted brackets to be preserved")
	}

	got, err = e.EnforceWithMatcher(matcher, "alice", "x[0]", "read")
	if err != nil {
		t.Fatalf("runtime matcher returned error: %v", err)
	}
	if !got {
		t.Errorf("runtime matcher: expected quoted brackets to be preserved")
	}
}

// TestNormalizationEvalSubruleBackslashAndComment verifies that sub-rules stored
// as policy data go through the same pipeline: comments are stripped and
// backslashes inside quoted literals are handled consistently.
func TestNormalizationEvalSubruleBackslashAndComment(t *testing.T) {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub_rule, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "eval(p.sub_rule) && r.obj == p.obj && r.act == p.act")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	if _, err := e.AddPolicy("r.sub == 'a\\b' # sub-rule comment", "data1", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	got, err := e.Enforce("a\\b", "data1", "read")
	if err != nil {
		t.Fatalf("Enforce returned error: %v", err)
	}
	if !got {
		t.Errorf("expected eval sub-rule with backslash and comment to match")
	}
}

// TestNormalizationBackslashAcrossEntries verifies that a backslash-containing
// literal evaluates identically whether it comes from the model file, a runtime
// matcher or a management query.
func TestNormalizationBackslashAcrossEntries(t *testing.T) {
	matcher := "r.obj == 'a\\b' && r.sub == p.sub"
	e := newNormalizationEnforcer(t, matcher)
	_, _ = e.AddPolicy("alice", "a\\b", "read")

	got, err := e.Enforce("alice", "a\\b", "read")
	if err != nil {
		t.Fatalf("model matcher returned error: %v", err)
	}
	if !got {
		t.Errorf("model matcher: expected backslash literal to match")
	}

	got, err = e.EnforceWithMatcher(matcher, "alice", "a\\b", "read")
	if err != nil {
		t.Fatalf("runtime matcher returned error: %v", err)
	}
	if !got {
		t.Errorf("runtime matcher: expected backslash literal to match")
	}

	res, err := e.GetFilteredNamedPolicyWithMatcher("p", "p.obj == 'a\\b'")
	if err != nil {
		t.Fatalf("management query returned error: %v", err)
	}
	if len(res) != 1 {
		t.Errorf("management query: expected one matching policy, got %v", res)
	}
}
