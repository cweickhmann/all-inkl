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

// globalMu serializes all KAS API calls across all Provider instances.
// KAS flood protection is per-account, so a single global gate is correct.
var (
	globalMu         sync.Mutex
	globalLastCall   time.Time
	globalFloodDelay time.Duration
)

// Provider facilitates DNS record manipulation with all-ink.com.
type Provider struct {
	KasUsername string `json:"kas_username,omitempty"`
	KasPassword string `json:"kas_password,omitempty"`
}

// waitForFloodDelay blocks until it is safe to make the next KAS API call,
// then records the current time. Must be called before every SOAP request.
func (p *Provider) waitForFloodDelay() {
	globalMu.Lock()
	defer globalMu.Unlock()
	// Default to 2.5s if no flood delay has been received from the API yet
	delay := globalFloodDelay
	if delay == 0 {
		delay = 2500 * time.Millisecond
	}
	if !globalLastCall.IsZero() {
		elapsed := time.Since(globalLastCall)
		if elapsed < delay {
			time.Sleep(delay - elapsed)
		}
	}
	globalLastCall = time.Now()
}

// updateFloodDelay reads the KasFloodDelay value from a parsed API response
// map and updates the global flood delay with a small safety buffer.
// KasFloodDelay is nested inside the "Response" item's value map.
func (p *Provider) updateFloodDelay(itemList []interface{}) {
	for _, item := range itemList {
		mitem, _ := item.(map[string]interface{})
		keyMap, _ := mitem["key"].(map[string]interface{})
		key, _ := keyMap["#text"].(string)
		if key != "Response" {
			continue
		}
		// Response value is itself a map with nested items
		val, _ := mitem["value"].(map[string]interface{})
		innerItems := val["item"]
		var innerList []interface{}
		switch v := innerItems.(type) {
		case []interface{}:
			innerList = v
		case map[string]interface{}:
			innerList = []interface{}{v}
		}
		for _, inner := range innerList {
			imap, _ := inner.(map[string]interface{})
			ikey, _ := imap["key"].(map[string]interface{})
			iname, _ := ikey["#text"].(string)
			if iname == "KasFloodDelay" {
				ival, _ := imap["value"].(map[string]interface{})
				switch v := ival["#text"].(type) {
				case float64:
					globalMu.Lock()
					globalFloodDelay = time.Duration(v*1000+200) * time.Millisecond
					globalMu.Unlock()
				case string:
					// ignore string representation
				}
				return
			}
		}
		return
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
