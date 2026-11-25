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

	casbinerrors "github.com/casbin/casbin/v3/errors"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// Stable error values are re-exported from the root Casbin package as well.
var (
	ErrNotImplemented          = casbinerrors.ErrNotImplemented
	ErrTransactionNotSupported = casbinerrors.ErrTransactionNotSupported
	ErrDegradedPolicyWrite     = casbinerrors.ErrDegradedPolicyWrite
	ErrPolicyRollbackFailed    = casbinerrors.ErrPolicyRollbackFailed
)

type policyWriteError struct {
	operation      error
	rollbackErrors []error
}

func newPolicyWriteError(operation error, rollbackErrors ...error) error {
	var errs []error
	for _, err := range rollbackErrors {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return &policyWriteError{operation: operation, rollbackErrors: errs}
}

func (e *policyWriteError) Error() string {
	message := e.operation.Error()
	for _, err := range e.rollbackErrors {
		message += "; rollback error: " + err.Error()
	}
	return message
}

func (e *policyWriteError) Unwrap() error {
	return e.operation
}

func (e *policyWriteError) Is(target error) bool {
	if stderrors.Is(e.operation, target) {
		return true
	}
	for _, err := range e.rollbackErrors {
		if stderrors.Is(err, target) {
			return true
		}
	}
	return false
}

type policyWriteResult struct {
	added    bool
	warnings []error
}

type policyRuleStorage interface {
	AddPolicy(sec string, ptype string, rule []string) error
	RemovePolicy(sec string, ptype string, rule []string) error
}

type adapterPolicyStorage struct {
	adapter persist.Adapter
}

func (s adapterPolicyStorage) AddPolicy(sec string, ptype string, rule []string) error {
	return s.adapter.AddPolicy(sec, ptype, rule)
}

func (s adapterPolicyStorage) RemovePolicy(sec string, ptype string, rule []string) error {
	return s.adapter.RemovePolicy(sec, ptype, rule)
}

type contextPolicyStorage struct {
	ctx     context.Context
	adapter persist.ContextAdapter
}

func (s contextPolicyStorage) AddPolicy(sec string, ptype string, rule []string) error {
	return s.adapter.AddPolicyCtx(s.ctx, sec, ptype, rule)
}

func (s contextPolicyStorage) RemovePolicy(sec string, ptype string, rule []string) error {
	return s.adapter.RemovePolicyCtx(s.ctx, sec, ptype, rule)
}

func (e *Enforcer) degradedPolicyWritesAllowed() bool {
	degrader, ok := e.adapter.(persist.DegradedPolicyWriter)
	return ok && degrader.AllowDegradedPolicyWrites()
}

func degradedPolicyWriteWarning(cause error) error {
	return fmt.Errorf(
		"%w: adapter returned %v; the rule exists only in memory until SavePolicy succeeds",
		casbinerrors.ErrDegradedPolicyWrite,
		cause,
	)
}

// applyNewPolicyRule updates the in-memory model and derived role state. If a
// later step fails, it removes the rule again and rebuilds role links so the
// caller never observes a partially applied add.
func (e *Enforcer) applyNewPolicyRule(sec string, ptype string, rule []string, validateConstraints bool) (err error) {
	if err = e.model.AddPolicy(sec, ptype, rule); err != nil {
		return err
	}

	defer func() {
		if err == nil {
			return
		}
		if rollbackErr := e.rollbackAppliedNewPolicyRule(sec, ptype, rule); rollbackErr != nil {
			err = newPolicyWriteError(err, rollbackErr)
		}
	}()

	if sec == "g" {
		if err = e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, [][]string{rule}); err != nil {
			return err
		}

		if validateConstraints {
			if err = e.validateConstraintsForGroupingPolicy(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *Enforcer) rollbackAppliedNewPolicyRule(sec string, ptype string, rule []string) error {
	if _, err := e.model.RemovePolicy(sec, ptype, rule); err != nil {
		return fmt.Errorf("remove policy from memory during rollback: %w", err)
	}

	if sec == "g" {
		if err := e.BuildRoleLinks(); err != nil {
			return fmt.Errorf("rebuild role links during rollback: %w", err)
		}
	}

	return nil
}

// commitNewPolicyRule makes one storage write and the in-memory update a
// rollbackable unit. Transactional adapters get a real storage transaction;
// other adapters use RemovePolicy as a compensating operation.
func (e *Enforcer) commitNewPolicyRule(
	ctx context.Context,
	sec string,
	ptype string,
	rule []string,
	storage policyRuleStorage,
	validateConstraints bool,
) (policyWriteResult, error) {
	if txAdapter, ok := e.adapter.(persist.TransactionalAdapter); ok {
		return e.commitTransactionalNewPolicy(ctx, txAdapter, sec, ptype, rule, storage, validateConstraints)
	}

	return e.commitCompensatingNewPolicy(sec, ptype, rule, storage, validateConstraints)
}

func (e *Enforcer) commitCompensatingNewPolicy(
	sec string,
	ptype string,
	rule []string,
	storage policyRuleStorage,
	validateConstraints bool,
) (policyWriteResult, error) {
	result := policyWriteResult{added: true}

	if err := storage.AddPolicy(sec, ptype, rule); err != nil {
		if persist.IsNotImplemented(err) && e.degradedPolicyWritesAllowed() {
			result.warnings = append(result.warnings, degradedPolicyWriteWarning(err))
			if applyErr := e.applyNewPolicyRule(sec, ptype, rule, validateConstraints); applyErr != nil {
				return policyWriteResult{}, applyErr
			}
			return result, nil
		}

		return policyWriteResult{}, err
	}

	if err := e.applyNewPolicyRule(sec, ptype, rule, validateConstraints); err != nil {
		if rollbackErr := storage.RemovePolicy(sec, ptype, rule); rollbackErr != nil {
			wrappedRollbackErr := fmt.Errorf(
				"%w: remove %v/%v during compensation: %v",
				casbinerrors.ErrPolicyRollbackFailed, sec, ptype, rollbackErr,
			)
			return policyWriteResult{}, newPolicyWriteError(err, wrappedRollbackErr)
		}
		return policyWriteResult{}, err
	}

	return result, nil
}

func (e *Enforcer) commitTransactionalNewPolicy(
	ctx context.Context,
	txAdapter persist.TransactionalAdapter,
	sec string,
	ptype string,
	rule []string,
	fallbackStorage policyRuleStorage,
	validateConstraints bool,
) (policyWriteResult, error) {
	txCtx, err := txAdapter.BeginTransaction(ctx)
	if err != nil {
		if stderrors.Is(err, casbinerrors.ErrTransactionNotSupported) {
			return e.commitCompensatingNewPolicy(
				sec,
				ptype,
				rule,
				fallbackStorage,
				validateConstraints,
			)
		}
		return policyWriteResult{}, err
	}

	result := policyWriteResult{added: true}
	txStorage := adapterPolicyStorage{adapter: txCtx.GetAdapter()}

	if err := txStorage.AddPolicy(sec, ptype, rule); err != nil {
		_ = txCtx.Rollback()

		if persist.IsNotImplemented(err) && e.degradedPolicyWritesAllowed() {
			result.warnings = append(result.warnings, degradedPolicyWriteWarning(err))
			if applyErr := e.applyNewPolicyRule(sec, ptype, rule, validateConstraints); applyErr != nil {
				return policyWriteResult{}, applyErr
			}
			return result, nil
		}

		return policyWriteResult{}, err
	}

	if err := e.applyNewPolicyRule(sec, ptype, rule, validateConstraints); err != nil {
		if rollbackErr := txCtx.Rollback(); rollbackErr != nil {
			wrappedRollbackErr := fmt.Errorf("%w: %v", casbinerrors.ErrPolicyRollbackFailed, rollbackErr)
			return policyWriteResult{}, newPolicyWriteError(err, wrappedRollbackErr)
		}
		return policyWriteResult{}, err
	}

	if err := txCtx.Commit(); err != nil {
		memoryRollbackErr := e.rollbackAppliedNewPolicyRule(sec, ptype, rule)
		storageRollbackErr := txCtx.Rollback()

		errs := []error{err}
		if memoryRollbackErr != nil {
			errs = append(errs, fmt.Errorf("rollback memory after commit failure: %w", memoryRollbackErr))
		}
		if storageRollbackErr != nil && !stderrors.Is(storageRollbackErr, casbinerrors.ErrTransactionNotSupported) {
			errs = append(errs, fmt.Errorf("%w: %v", casbinerrors.ErrPolicyRollbackFailed, storageRollbackErr))
		}
		if len(errs) == 1 {
			return policyWriteResult{}, err
		}
		return policyWriteResult{}, newPolicyWriteError(errs[0], errs[1:]...)
	}

	return result, nil
}
