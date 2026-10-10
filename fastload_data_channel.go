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
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Data Session Parcel Stream
type fastLoadBatch struct {
	body []byte
	w    *bufferWriter
	rows int
}

func (b *fastLoadBatch) reset() {
	b.w.setPosition(0)
	b.rows = 0
}

// Data Channel holds the connection + buffer
type fastLoadDataChannel struct {
	conn         *teradataConnection
	encoders     []*fastLoadColumnEncoder
	maxParcelLen int // header + fastLoadMaxRowBytes
	send         func(*fastLoadBatch) (int64, error)

	cur     *fastLoadBatch
	pending chan *fastLoadBatch
	free    chan *fastLoadBatch
	done    chan struct{}

	rowsAccepted atomic.Int64
	errMu        sync.Mutex
	err          error // first failure
	broken       atomic.Bool
	closeOnce    sync.Once
	closeErr     error
}

func newFastLoadDataChannel(conn *teradataConnection, encoders []*fastLoadColumnEncoder, config *Config) (*fastLoadDataChannel, error) {
	bodyLen := conn.capabilities.maxRequestMessageBodySize
	if config.MaxMessageSize > 0 && config.MaxMessageSize < bodyLen {
		bodyLen = config.MaxMessageSize
	}
	bodyLen -= fastLoadRespondParcel.getLength()

	c, err := startFastLoadDataChannel(encoders, bodyLen, nil)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	c.send = c.sendBatch
	return c, nil
}

func startFastLoadDataChannel(encoders []*fastLoadColumnEncoder, bodyLen int, send func(*fastLoadBatch) (int64, error)) (*fastLoadDataChannel, error) {
	maxParcelLen := fastLoadParcelHeaderLen + fastLoadMaxRowBytes(encoders)
	if maxParcelLen > fastLoadMaxParcelLen {
		return nil, fmt.Errorf("%w: potential row size of %d bytes exceeds %d", ErrFastLoadUnsupported, maxParcelLen, fastLoadMaxParcelLen)
	}
	if maxParcelLen > bodyLen {
		return nil, fmt.Errorf("%w: potential row size of %d bytes exceeds the %d byte message body", ErrFastLoadUnsupported, maxParcelLen, bodyLen)
	}
	c := &fastLoadDataChannel{
		encoders:     encoders,
		maxParcelLen: maxParcelLen,
		send:         send,
		pending:      make(chan *fastLoadBatch, fastLoadBuffersPerSession),
		free:         make(chan *fastLoadBatch, fastLoadBuffersPerSession),
		done:         make(chan struct{}),
	}
	for i := range fastLoadBuffersPerSession {
		body := make([]byte, bodyLen)
		b := &fastLoadBatch{body: body, w: newBufferWriter(body)}
		if i == 0 {
			c.cur = b
		} else {
			c.free <- b
		}
	}
	go c.run()
	return c, nil
}

func (c *fastLoadDataChannel) run() {
	defer close(c.done)
	for b := range c.pending {
		if c.failure() == nil {
			if n, err := c.send(b); err != nil {
				c.setFailure(err)
			} else {
				c.rowsAccepted.Add(n)
			}
		}
		b.reset()
		c.free <- b
	}
}

// Encode and add row to buffer
func (c *fastLoadDataChannel) pushRow(ctx context.Context, rowNumber int32, values []driver.Value) error {
	if err := c.failure(); err != nil {
		return err
	}
	if c.cur == nil {
		if err := c.acquire(ctx); err != nil {
			return err
		}
	}
	if len(c.cur.body)-c.cur.w.position() < c.maxParcelLen {
		if err := c.dispatch(ctx); err != nil {
			return err
		}
	}
	b := c.cur
	start := b.w.position()
	b.w.u16(uint16(flavorIndicData))
	b.w.skip(2) // length added below
	if err := writeFastLoadRow(b.w, c.encoders, values, rowNumber); err != nil {
		b.w.setPosition(start) // rollback the partial row
		return fmt.Errorf("fastload row %d: %w", rowNumber, err)
	}
	binary.BigEndian.PutUint16(b.body[start+2:], uint16(b.w.position()-start))
	b.rows++
	return nil
}

func (c *fastLoadDataChannel) dispatch(ctx context.Context) error {
	if c.cur == nil || c.cur.rows == 0 {
		return nil
	}
	c.pending <- c.cur
	c.cur = nil
	return c.acquire(ctx)
}

func (c *fastLoadDataChannel) acquire(ctx context.Context) error {
	select {
	case c.cur = <-c.free:
		return nil
	case <-ctx.Done():
		return c.interrupt(ctx.Err())
	}
}

func (c *fastLoadDataChannel) wait(ctx context.Context) error {
	held := make([]*fastLoadBatch, 0, fastLoadBuffersPerSession-1)
	defer func() {
		for _, b := range held {
			c.free <- b
		}
	}()
	inHand := 0
	if c.cur != nil {
		inHand = 1
	}
	for len(held)+inHand < fastLoadBuffersPerSession {
		select {
		case b := <-c.free:
			held = append(held, b)
		case <-ctx.Done():
			return c.interrupt(ctx.Err())
		}
	}
	return c.failure()
}

// Send one batch and check for error response
func (c *fastLoadDataChannel) sendBatch(b *fastLoadBatch) (int64, error) {
	n, err := c.sendBatchIO(b)
	if err != nil && isConnectionError(err) {
		// If connection error then this channel is done
		c.broken.Store(true)
		if cause := c.failure(); cause != nil && isDeadlineErr(err) {
			return 0, cause
		}
	}
	return n, err
}

// Send one batch over the wire
func (c *fastLoadDataChannel) sendBatchIO(b *fastLoadBatch) (int64, error) {
	err := c.conn.writeLanMessage(
		c.conn.newLanHeaderStart(),
		&fastLoadRowsParcel{data: b.body[:b.w.position()]},
		fastLoadRespondParcel,
	)
	if err != nil {
		return 0, err
	}
	parcels, _, err := c.conn.readLanMessage()
	if err != nil {
		return 0, err
	}
	n, _ := activityCountFromStatusParcels(parcels)
	return int64(n), nil
}

func (c *fastLoadDataChannel) failure() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.err
}

// Call when context is cancelled
func (c *fastLoadDataChannel) interrupt(err error) error {
	c.setFailure(err)
	c.broken.Store(true)
	if c.conn != nil && c.conn.netConn != nil {
		c.conn.netConn.SetDeadline(time.Now())
	}
	return err
}

func (c *fastLoadDataChannel) setFailure(err error) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.err == nil {
		c.err = err
	}
}

// Store the channel letting any IO finish
func (c *fastLoadDataChannel) close(ctx context.Context) error {
	c.closeOnce.Do(func() {
		close(c.pending)
		select {
		case <-c.done:
		case <-ctx.Done():
			c.interrupt(ctx.Err())
			<-c.done
		}
		if c.conn == nil {
			return
		}
		if c.broken.Load() {
			c.conn.closed.Store(true)
			c.closeErr = c.conn.netConn.Close()
			return
		}
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}
