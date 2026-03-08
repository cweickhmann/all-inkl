// Package libdnstemplate implements a DNS record management client compatible
// with the libdns interfaces for all-ink.com.
package allinkl

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with all-ink.com.
type Provider struct {
	KasUsername string `json:"kas_username,omitempty"`
	KasPassword string `json:"kas_password,omitempty"`

	// mu serializes API calls to respect KAS flood delay
	mu         sync.Mutex
	lastCall   time.Time
	floodDelay time.Duration
}

// waitForFloodDelay blocks until it is safe to make the next KAS API call,
// then records the current time. Must be called before every SOAP request.
func (p *Provider) waitForFloodDelay() {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Default to 1.5s if no flood delay has been received from the API yet
	delay := p.floodDelay
	if delay == 0 {
		delay = 1500 * time.Millisecond
	}
	if !p.lastCall.IsZero() {
		elapsed := time.Since(p.lastCall)
		if elapsed < delay {
			time.Sleep(delay - elapsed)
		}
	}
	p.lastCall = time.Now()
}

// updateFloodDelay reads the KasFloodDelay value from a parsed API response
// map and updates the provider's flood delay with a small safety buffer.
func (p *Provider) updateFloodDelay(itemList []interface{}) {
	for _, item := range itemList {
		mitem, _ := item.(map[string]interface{})
		keyMap, _ := mitem["key"].(map[string]interface{})
		key, _ := keyMap["#text"].(string)
		if key == "Response" {
			val, _ := mitem["value"].(map[string]interface{})
			if fd, exists := val["KasFloodDelay"]; exists {
				switch v := fd.(type) {
				case float64:
					p.mu.Lock()
					p.floodDelay = time.Duration(v*1000+200) * time.Millisecond
					p.mu.Unlock()
				}
			}
			return
		}
	}
}
// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	libdnsRecords, err := p.GetAllRecords(ctx, zone)
	return libdnsRecords, err
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Make sure to return RR-type-specific structs, not libdns.RR structs.

	var createdRecords []libdns.Record
	for _, record := range records {
		recs, err := p.AppendRecord(ctx, zone, record)
		if err != nil {
			return nil, fmt.Errorf("failed to append record %v: %w", record, err)
		}
		createdRecords = append(createdRecords, recs...)
	}
	return createdRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Make sure to return RR-type-specific structs, not libdns.RR structs.

	var updatedRecords []libdns.Record
	for _, record := range records {
		recs, err := p.SetRecord(ctx, zone, record)
		if err != nil {
			return nil, fmt.Errorf("failed to set record %v: %w", record, err)
		}
		updatedRecords = append(updatedRecords, recs...)
	}
	return updatedRecords, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deletedRecords []libdns.Record
	for _, record := range records {
		recs, err := p.DeleteRecord(ctx, zone, record)
		if err != nil {
			return nil, fmt.Errorf("failed to delete record %v: %w", record, err)
		}
		deletedRecords = append(deletedRecords, recs...)
	}
	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
