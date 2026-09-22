// Copyright 2026 Andrew Lapham
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package teradata

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidConn           = errors.New("invalid connection")
	ErrShortRead             = errors.New("short read")
	ErrReadFail              = errors.New("read failed")
	ErrInternal              = errors.New("internal driver error")
	ErrInvalidResponse       = errors.New("invalid response")
	ErrNoSupportAuth         = errors.New("no support auth mechanisms")
	ErrNoSecureChannel       = errors.New("unable to acquire a secure channel")
	ErrNotImplemented        = errors.New("not implemented")
	ErrInvalidRead           = errors.New("invalid read")
	ErrInvalidMetadata       = errors.New("invalid metadata from db")
	ErrInvalidParamIndex     = errors.New("invalid param index")
	ErrTransactionInProgress = errors.New("transaction already in progress")
	ErrTlsUpgradeFail        = errors.New("tls websocket upgrade failure")
	ErrTlsCaFail             = errors.New("tls CA verification failed")
	ErrTlsHostFail           = errors.New("tls hostname verification failed")
	ErrInvalidLobSize        = errors.New("invalid lob length on read")
	ErrTd2InvalidAlg         = errors.New("only AES with GCM96 is supported")
)

type TeradataError struct {
	Code    uint16
	Message string
}

func (e *TeradataError) Error() string {
	return fmt.Sprintf("Error %d: %s", e.Code, e.Message)
}

func (p *errorResponseParcel) asTeradataError() *TeradataError {
	return &TeradataError{
		Code:    p.code,
		Message: p.message,
	}
}

type TeradataConnectionError struct {
	Message string
}

func (e *TeradataConnectionError) Error() string {
	return fmt.Sprintf("TeradataConnectionError: %s", e.Message)
}

func wrapConnectionError(err error) *TeradataConnectionError {
	return &TeradataConnectionError{Message: err.Error()}
}

func isConnectionError(err error) bool {
	_, ok := errors.AsType[*TeradataError](err)
	return !ok
}

func isTeradataErrorCode(err error, code int) bool {
	if terr, ok := err.(*TeradataError); ok {
		return int(terr.Code) == code
	}
	return false
}
