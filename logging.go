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
	"context"
	"log/slog"
)

const logLevelTrace = slog.Level(-8)

type noopLogger struct{}

func (h noopLogger) Enabled(ctx context.Context, l slog.Level) bool  { return false }
func (h noopLogger) Handle(ctx context.Context, r slog.Record) error { return nil }
func (h noopLogger) WithAttrs(attrs []slog.Attr) slog.Handler        { return h }
func (h noopLogger) WithGroup(name string) slog.Handler              { return h }

func newNoopLogger() *slog.Logger {
	return slog.New(noopLogger{})
}
