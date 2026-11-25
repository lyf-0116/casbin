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

import (
	stderrors "errors"

	casbinerrors "github.com/casbin/casbin/v3/errors"
)

// Sentinel errors are re-exported from the top-level errors package so adapter
// implementations can depend on the persist package alone.
var (
	ErrNotImplemented          = casbinerrors.ErrNotImplemented
	ErrTransactionNotSupported = casbinerrors.ErrTransactionNotSupported
	ErrDegradedPolicyWrite     = casbinerrors.ErrDegradedPolicyWrite
	ErrPolicyRollbackFailed    = casbinerrors.ErrPolicyRollbackFailed
)

// IsNotImplemented reports whether err is the stable not-implemented value,
// including errors that wrap it.
func IsNotImplemented(err error) bool {
	return stderrors.Is(err, ErrNotImplemented)
}
