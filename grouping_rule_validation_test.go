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
	"os"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v3/model"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
)

const conditionalDomainModelText = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _, (_, _)

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`

const domainModelText = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`

func newFileBackedEnforcer(t *testing.T, modelText string) (*Enforcer, string) {
	t.Helper()

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}

	policyPath := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(policyPath, []byte(""), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	e, err := NewEnforcer(m, fileadapter.NewAdapter(policyPath))
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return e, policyPath
}

// TestConditionalRoleRejectsHalfBakedRule verifies that a grouping rule
// missing the domain/condition fields declared by a conditional role
// definition is rejected before it enters the in-memory policy or the file,
// so the saved policy file can always be loaded again.
func TestConditionalRoleRejectsHalfBakedRule(t *testing.T) {
	e, policyPath := newFileBackedEnforcer(t, conditionalDomainModelText)

	ok, err := e.AddGroupingPolicy("alice", "test1", "domain1", "_", "2999-12-30 00:00:00")
	if !ok || err != nil {
		t.Fatalf("valid conditional grouping rule rejected: ok=%v err=%v", ok, err)
	}

	// Only two fields for a five-field conditional role definition.
	if ok, err := e.AddGroupingPolicy("bob", "role2"); err == nil || ok {
		t.Fatalf("half-baked conditional rule must be rejected: ok=%v err=%v", ok, err)
	}

	g, err := e.GetNamedGroupingPolicy("g")
	if err != nil {
		t.Fatalf("GetNamedGroupingPolicy: %v", err)
	}
	if len(g) != 1 {
		t.Fatalf("rejected rule leaked into in-memory policy: %v", g)
	}

	if err := e.SavePolicy(); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	m, err := model.NewModelFromString(conditionalDomainModelText)
	if err != nil {
		t.Fatalf("reload model: %v", err)
	}
	reloadedEnforcer, err := NewEnforcer(m, fileadapter.NewAdapter(policyPath))
	if err != nil {
		t.Fatalf("policy written by SavePolicy must load back: %v", err)
	}
	reloadedRules, err := reloadedEnforcer.GetNamedGroupingPolicy("g")
	if err != nil {
		t.Fatalf("reloaded GetNamedGroupingPolicy: %v", err)
	}
	if len(reloadedRules) != 1 {
		t.Fatalf("reloaded grouping policy mismatch: %v", reloadedRules)
	}
}

// TestRuntimeDomainRoleRejectsMissingDomain verifies the same guarantee for
// a regular (non-conditional) role definition with a domain field.
func TestRuntimeDomainRoleRejectsMissingDomain(t *testing.T) {
	e, _ := newFileBackedEnforcer(t, domainModelText)

	if ok, err := e.AddGroupingPolicy("alice", "admin", "domain1"); err != nil || !ok {
		t.Fatalf("valid domain grouping rule rejected: ok=%v err=%v", ok, err)
	}

	// Missing the domain for a three-field role definition.
	if ok, err := e.AddGroupingPolicy("bob", "admin"); err == nil || ok {
		t.Fatalf("domain-less rule must be rejected: ok=%v err=%v", ok, err)
	}

	g, err := e.GetNamedGroupingPolicy("g")
	if err != nil {
		t.Fatalf("GetNamedGroupingPolicy: %v", err)
	}
	if len(g) != 1 {
		t.Fatalf("rejected rule leaked into in-memory policy: %v", g)
	}

	// Custom data beyond the declared fields stays a supported caller feature.
	if ok, err := e.AddGroupingPolicy("carol", "admin", "domain2", "custom-data"); err != nil || !ok {
		t.Fatalf("custom data field must stay allowed: ok=%v err=%v", ok, err)
	}
}

// TestPolicyModificationValidatesRuleSize verifies that update and filtered
// write entry points apply the same up-front validation and never leave
// partial state behind.
func TestPolicyModificationValidatesRuleSize(t *testing.T) {
	e, _ := newFileBackedEnforcer(t, conditionalDomainModelText)

	if _, err := e.AddGroupingPolicy("alice", "test1", "domain1", "_", "2999-12-30 00:00:00"); err != nil {
		t.Fatalf("seed grouping rule: %v", err)
	}

	before, _ := e.GetNamedGroupingPolicy("g")

	// Update with an undersized new rule must be rejected without touching state.
	if ok, err := e.UpdateGroupingPolicy(
		[]string{"alice", "test1", "domain1", "_", "2999-12-30 00:00:00"},
		[]string{"alice", "test2"},
	); err == nil || ok {
		t.Fatalf("update to an undersized rule must be rejected: ok=%v err=%v", ok, err)
	}

	after, _ := e.GetNamedGroupingPolicy("g")
	if len(after) != len(before) {
		t.Fatalf("failed update changed policy state: before=%v after=%v", before, after)
	}

	// A filter window reaching past the declared fields must be rejected.
	if ok, err := e.RemoveFilteredGroupingPolicy(4, "x", "y"); err == nil || ok {
		t.Fatalf("out-of-bounds field filter must be rejected: ok=%v err=%v", ok, err)
	}

	// A correctly sized update still works.
	if ok, err := e.UpdateGroupingPolicy(
		[]string{"alice", "test1", "domain1", "_", "2999-12-30 00:00:00"},
		[]string{"alice", "test2", "domain1", "_", "2999-12-30 00:00:00"},
	); err != nil || !ok {
		t.Fatalf("valid grouping rule update failed: ok=%v err=%v", ok, err)
	}

	g, _ := e.GetNamedGroupingPolicy("g")
	if len(g) != 1 || g[0][1] != "test2" {
		t.Fatalf("grouping policy after valid update mismatch: %v", g)
	}
}
