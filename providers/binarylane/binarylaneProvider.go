package binarylane

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff2"
	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	"github.com/StackExchange/dnscontrol/v4/providers"
)

const (
	minimumTTL = 600
)

const (
	metaType        = "type"
	metaIncludePath = "includePath"
	metaWildcard    = "wildcard"
)

var defaultNS = []string{
	"ns1.binarylane.com.au",
	"ns2.binarylane.com.au",
	"ns3.binarylane.com.au",
}

func newDsp(conf map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	return newBinaryLane(conf, metadata)
}

// newBinaryLane creates the provider.
func newBinaryLane(m map[string]string, _ json.RawMessage) (*binarylaneProvider, error) {
	c := &binarylaneProvider{}

	c.apiToken = m["api_token"]

	if c.apiToken == "" {
		return nil, errors.New("missing binarylane api_token")
	}

	return c, nil
}

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanAutoDNSSEC:          providers.Cannot(),
	providers.CanGetZones:            providers.Can(),
	providers.CanConcur:              providers.Unimplemented(),
	providers.CanUseAlias:            providers.Can(),
	providers.CanUseCAA:              providers.Can(),
	providers.CanUseDS:               providers.Cannot(),
	providers.CanUseDSForChildren:    providers.Cannot(),
	providers.CanUseLOC:              providers.Cannot(),
	providers.CanUseNAPTR:            providers.Cannot(),
	providers.CanUsePTR:              providers.Cannot(),
	providers.CanUseSOA:              providers.Cannot(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanUseSSHFP:            providers.Cannot(), // FIXME: check
	providers.CanUseTLSA:             providers.Cannot(), // FIXME: check
	providers.CanUseHTTPS:            providers.Cannot(), // FIXME: check
	providers.CanUseSVCB:             providers.Cannot(), // FIXME: check
	providers.DocCreateDomains:       providers.Cannot(), // FIXME: support this
	providers.DocDualHost:            providers.Cannot(),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	const providerName = "BINARYLANE"
	const providerMaintainer = "@hmoffatt"
	fns := providers.DspFuncs{
		Initializer:   newDsp,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType(providerName, fns, features)
	providers.RegisterMaintainer(providerName, providerMaintainer)
}

// GetNameservers returns the nameservers for a domain.
func (c *binarylaneProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	nameservers, err := c.getNameservers(domain)
	if err != nil {
		return nil, err
	}
	return models.ToNameservers(nameservers)
}

func genComparable(rec *models.RecordConfig) string {
	if rec.Type == "PORKBUN_URLFWD" {
		return fmt.Sprintf("type=%s includePath=%s wildcard=%s", rec.Metadata[metaType], rec.Metadata[metaIncludePath], rec.Metadata[metaWildcard])
	}
	return ""
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (c *binarylaneProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existingRecords models.Records) ([]*models.Correction, int, error) {
	var corrections []*models.Correction

	// Block changes to NS records for base domain
	checkNSModifications(dc)

	// Make sure TTL larger than the minimum TTL
	for _, record := range dc.Records {
		record.TTL = fixTTL(record.TTL)
	}

	changes, actualChangeCount, err := diff2.ByRecord(existingRecords, dc, genComparable)
	if err != nil {
		return nil, 0, err
	}
	for _, change := range changes {
		var corr *models.Correction
		switch change.Type {
		case diff2.REPORT:
			corr = &models.Correction{Msg: change.MsgsJoined}
		case diff2.CREATE:
			req, err := toReq(change.New[0])
			if err != nil {
				return nil, 0, err
			}
			corr = &models.Correction{
				Msg: change.Msgs[0],
				F: func() error {
					return c.createRecord(dc.Name, req)
				},
			}
		case diff2.CHANGE:
			id := change.Old[0].Original.(*domainRecord).ID
			req, err := toReq(change.New[0])
			if err != nil {
				return nil, 0, err
			}
			corr = &models.Correction{
				Msg: fmt.Sprintf("%s, binarylane ID: %d", change.Msgs[0], id),
				F: func() error {
					return c.modifyRecord(dc.Name, id, req)
				},
			}
		case diff2.DELETE:
			id := change.Old[0].Original.(*domainRecord).ID
			corr = &models.Correction{
				Msg: fmt.Sprintf("%s, binarylane ID: %d", change.Msgs[0], id),
				F: func() error {
					return c.deleteRecord(dc.Name, id)
				},
			}
		default:
			panic(fmt.Sprintf("unhandled change.Type %s", change.Type))
		}
		corrections = append(corrections, corr)
	}

	return corrections, actualChangeCount, nil
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (c *binarylaneProvider) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {
	records, err := c.getRecords(domain)
	if err != nil {
		return nil, err
	}
	existingRecords := make([]*models.RecordConfig, 0)
	for i := range records {
		newr, err := toRc(domain, &records[i])
		if err != nil {
			return nil, err
		}
		existingRecords = append(existingRecords, newr)
	}

	return existingRecords, nil
}

// parses the binarylane format into our standard RecordConfig
func toRc(domain string, r *domainRecord) (*models.RecordConfig, error) {
	rc := &models.RecordConfig{
		Type:         r.Type,
		TTL:          uint32(r.TTL),
		MxPreference: uint16(r.Prio),
		SrvPriority:  uint16(r.Prio),
		SrvWeight:    uint16(r.Weight),
		SrvPort:      uint16(r.Port),
		CaaTag:       r.Tag,
		CaaFlag:      uint8(r.Flags),
		Original:     r,
	}
	rc.SetLabel(r.Name, domain)

	var err error
	switch rtype := r.Type; rtype { // #rtype_variations
	case "TXT":
		err = rc.SetTargetTXT(r.Content)
	case "MX", "CNAME", "ALIAS", "NS":
		if strings.HasSuffix(r.Content, ".") {
			err = rc.SetTarget(r.Content)
		} else {
			err = rc.SetTarget(r.Content + ".")
		}
	case "CAA":
		// 0, issue, "letsencrypt.org"
		c := strings.Split(r.Content, " ")

		caaFlag, _ := strconv.ParseUint(c[0], 10, 8)
		rc.CaaFlag = uint8(caaFlag)
		rc.CaaTag = c[1]
		err = rc.SetTarget(strings.ReplaceAll(c[2], "\"", ""))
	case "TLSA":
		// 0 0 0 00000000000000000000000
		c := strings.Split(r.Content, " ")

		tlsaUsage, _ := strconv.ParseUint(c[0], 10, 8)
		rc.TlsaUsage = uint8(tlsaUsage)
		tlsaSelector, _ := strconv.ParseUint(c[1], 10, 8)
		rc.TlsaSelector = uint8(tlsaSelector)
		tlsaMatchingType, _ := strconv.ParseUint(c[2], 10, 8)
		rc.TlsaMatchingType = uint8(tlsaMatchingType)
		err = rc.SetTarget(c[3])
	case "SRV":
		// 5 5060 sip.example.com
		c := strings.Split(r.Content, " ")

		srvWeight, _ := strconv.ParseUint(c[0], 10, 16)
		rc.SrvWeight = uint16(srvWeight)
		srvPort, _ := strconv.ParseUint(c[1], 10, 16)
		rc.SrvPort = uint16(srvPort)
		err = rc.SetTarget(c[2])
	case "HTTPS":
		fallthrough
	case "SVCB":
		// 5 . ech=AAAAABBBBB...
		c := strings.Split(r.Content, " ")

		svcPriority, _ := strconv.ParseUint(c[0], 10, 16)
		rc.SvcPriority = uint16(svcPriority)
		rc.SvcParams = c[2]
		err = rc.SetTarget(c[1])
	default:
		err = rc.SetTarget(r.Content)
	}
	return rc, err
}

// toReq takes a RecordConfig and turns it into the native format used by the API.
func toReq(rc *models.RecordConfig) (requestParams, error) {
	req := requestParams{
		"type": rc.Type,
		"name": rc.GetLabel(),
		"data": rc.GetTargetField(),
		"ttl":  rc.TTL,
	}

	switch rc.Type { // #rtype_variations
	case "A", "AAAA", "NS", "ALIAS", "CNAME":
	// Nothing special.
	case "TXT":
		req["data"] = rc.GetTargetTXTJoined()
	case "MX":
		req["priority"] = int(rc.MxPreference)
	case "SRV":
		req["priority"] = strconv.Itoa(int(rc.SrvPriority))
		req["data"] = fmt.Sprintf("%d %d %s", rc.SrvWeight, rc.SrvPort, rc.GetTargetField())
	case "CAA":
		req["data"] = fmt.Sprintf("%d %s \"%s\"", rc.CaaFlag, rc.CaaTag, rc.GetTargetField())
	case "TLSA":
		req["data"] = fmt.Sprintf("%d %d %d %s",
			rc.TlsaUsage, rc.TlsaSelector, rc.TlsaMatchingType, rc.GetTargetField())
	case "HTTPS":
		fallthrough
	case "SVCB":
		req["data"] = fmt.Sprintf("%d %s %s",
			rc.SvcPriority, rc.GetTargetField(), rc.SvcParams)
	default:
		return nil, fmt.Errorf("binarylane.toReq rtype %q unimplemented", rc.Type)
	}

	return req, nil
}

func checkNSModifications(dc *models.DomainConfig) {
	newList := make([]*models.RecordConfig, 0, len(dc.Records))
	for _, rec := range dc.Records {
		if rec.Type == "NS" && rec.GetLabelFQDN() == dc.Name {
			if strings.HasSuffix(rec.GetTargetField(), ".binarylane.com.au") {
				printer.Warnf("binarylane does not support modifying NS records on base domain. %s will not be added.\n", rec.GetTargetField())
			}
			continue
		}
		newList = append(newList, rec)
	}
	dc.Records = newList
}

func fixTTL(ttl uint32) uint32 {
	if ttl > minimumTTL {
		return ttl
	}
	return minimumTTL
}
