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
	"net"
	"time"
)

// Timeout on how long we wait for the server to ack a cancel:
const sendCancelAndDrainTimeout = 10 * time.Second

// Send cancel to server to abandoned the current request
func (s *teradataStatement) sendCancelAndDrain() error {
	err := s.conn.sendCancelAndDrain(s.requestNo)
	s.isOpenKeep = false
	return err
}

func (c *teradataConnection) sendCancelAndDrain(requestNo uint32) error {
	err := c.writeLanMessage(
		c.newLanHeaderCancel(requestNo),
		newCancelParcel(),
	)
	if err != nil {
		return err
	}

	c.netConn.SetReadDeadline(time.Now().Add(sendCancelAndDrainTimeout))
	defer c.netConn.SetReadDeadline(time.Time{})

	for {
		data, start, end, _, err := c.readLanMessageRaw()
		if err != nil {
			return err
		}
		reader := newBufferReader(data, start, end)
		err = checkErrorParcel(reader)
		if err != nil {
			c.config.Logger.Log(context.Background(), logLevelTrace, "CancelError", "error", err)
			return err
		}
		// Read the buffer to the end:
		for !reader.isDone() {
			parcelStart := reader.position()
			flavor, parcelLen, _ := readParcelHeader(reader)
			reader.seek(parcelStart + int(parcelLen))
			if flavor == uint16(flavorEndRequest) {
				//c.openKeepStatement = false
				return nil
			}
		}
	}
}

func (c *teradataConnection) runCancelable(ctx context.Context, fn func() error) error {
	if ctx.Done() == nil {
		return fn()
	}

	watcherDone := make(chan struct{})
	defer close(watcherDone)

	go func() {
		select {
		case <-ctx.Done():
			c.netConn.SetReadDeadline(time.Now())
		case <-watcherDone:
		}
	}()

	err := fn()

	if ctx.Err() != nil && isDeadlineErr(err) {
		c.netConn.SetReadDeadline(time.Time{})
		_ = c.sendCancelAndDrain(c.sameRequestNumber())
		return ctx.Err()
	}

	c.netConn.SetReadDeadline(time.Time{})
	return err
}

func isDeadlineErr(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
