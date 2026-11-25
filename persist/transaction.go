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

package persist

import "context"

// TransactionalAdapter defines the interface for adapters that support transactions.
// Adapters implementing this interface can participate in Casbin transactions.
type TransactionalAdapter interface {
	Adapter
	// BeginTransaction starts a new transaction and returns a transaction context.
	BeginTransaction(ctx context.Context) (TransactionContext, error)
}

// DegradedPolicyWriter is an explicit declaration that an adapter is allowed
// to complete a policy write in a weaker, non-durable mode when incremental
// persistence returns ErrNotImplemented.
//
// Casbin fails closed when an adapter does not implement this interface (or
// the method returns false). Adapters that can reconstruct state later, for
// example by writing the complete model with SavePolicy, may return true and
// surface the resulting degradation through Casbin's audit logger.
type DegradedPolicyWriter interface {
	Adapter
	// AllowDegradedPolicyWrites reports whether memory-only policy writes are
	// an accepted fallback for this adapter.
	AllowDegradedPolicyWrites() bool
}

// TransactionContext represents a database transaction context.
// It provides methods to commit or rollback the transaction and get an adapter
// that operates within this transaction.
type TransactionContext interface {
	// Commit commits the transaction.
	Commit() error
	// Rollback rolls back the transaction.
	Rollback() error
	// GetAdapter returns an adapter that operates within this transaction.
	GetAdapter() Adapter
}

// PolicyOperation represents a policy operation that can be buffered in a transaction.
type PolicyOperation struct {
	Type       OperationType // The type of operation (add, remove, update)
	Section    string        // The section of the policy (p, g)
	PolicyType string        // The policy type (p, p2, g, g2, etc.)
	Rules      [][]string    // The policy rules to operate on
	OldRules   [][]string    // For update operations, the old rules to replace
}

// OperationType represents the type of policy operation.
type OperationType int

const (
	// OperationAdd represents adding policy rules.
	OperationAdd OperationType = iota
	// OperationRemove represents removing policy rules.
	OperationRemove
	// OperationUpdate represents updating policy rules.
	OperationUpdate
)
