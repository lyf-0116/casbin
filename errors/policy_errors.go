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

package errors

import stderrors "errors"

// Policy persistence errors are compared with errors.Is instead of matching
// their human-readable messages.
var (
	// ErrNotImplemented is returned when an adapter deliberately does not
	// implement an optional persistence operation.
	ErrNotImplemented = stderrors.New("not implemented")

	// ErrTransactionNotSupported indicates that an adapter cannot start the
	// transaction requested by the enforcer.
	ErrTransactionNotSupported = stderrors.New("adapter does not support transactions")

	// ErrDegradedPolicyWrite records that a policy update was accepted in a
	// deliberately weaker mode, usually memory-only.
	ErrDegradedPolicyWrite = stderrors.New("degraded policy write")

	// ErrPolicyRollbackFailed means that compensating one side of a policy
	// write failed after the other side had already been changed.
	ErrPolicyRollbackFailed = stderrors.New("policy rollback failed")
)
