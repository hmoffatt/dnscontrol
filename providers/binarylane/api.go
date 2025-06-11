package binarylane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

const (
	baseURL = "https://api.binarylane.com.au/v2"
)

type binarylaneProvider struct {
	apiToken string
}

type requestParams map[string]any

type errorResponse struct {
	Type   string `json:"string"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

type domainRecord struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"data"`
	TTL     int32  `json:"ttl"`
	Prio    int32  `json:"priority"`
	Weight  int32  `json:"weight"`
	Port    int32  `json:"port"`
	Flags   int32  `json:"flags"`
	Tag     string `json:"tag"`
}

type recordResponse struct {
	// Also meta, links
	Records []domainRecord `json:"domain_records"`
}

type domainListRecord struct {
	Domain string `json:"name"`
}

type domainListResponse struct {
	Domains []domainListRecord `json:"domains"`
}

type nsResponse struct {
	Nameservers []string `json:"current_nameservers"`
}

func (c *binarylaneProvider) req(method string, endpoint string, body io.Reader) ([]byte, error) {
	client := &http.Client{}
	req, _ := http.NewRequest(method, baseURL+endpoint, body)
	req.Header.Add("Authorization", "Bearer "+c.apiToken)
	if body != nil {
		req.Header.Add("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}

	bodyString, _ := io.ReadAll(resp.Body)

	// Got error from API ?
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		var errResp errorResponse
		err = json.Unmarshal(bodyString, &errResp)
		if err == nil {
			return bodyString, fmt.Errorf("binarylane API error: %s URL:%s%s ", errResp.Title, req.Host, req.URL.RequestURI())
		}
	}

	return bodyString, nil
}

func (c *binarylaneProvider) get(endpoint string) ([]byte, error) {
	return c.req(http.MethodGet, endpoint, nil)
}

func (c *binarylaneProvider) delete(endpoint string) ([]byte, error) {
	return c.req(http.MethodDelete, endpoint, nil)
}

func (c *binarylaneProvider) post(endpoint string, params requestParams) ([]byte, error) {
	JSON, err := json.Marshal(params)
	if err != nil {
		return []byte{}, err
	}
	return c.req(http.MethodPost, endpoint, bytes.NewBuffer(JSON))
}

func (c *binarylaneProvider) put(endpoint string, params requestParams) ([]byte, error) {
	JSON, err := json.Marshal(params)
	if err != nil {
		return []byte{}, err
	}

	return c.req(http.MethodPut, endpoint, bytes.NewBuffer(JSON))
}

func (c *binarylaneProvider) createRecord(domain string, rec requestParams) error {
	if _, err := c.post(fmt.Sprintf("/domains/%s/records", domain), rec); err != nil {
		return fmt.Errorf("failed create record (binarylane): %w", err)
	}
	return nil
}

func (c *binarylaneProvider) deleteRecord(domain string, recordID int64) error {
	if _, err := c.delete(fmt.Sprintf("/domains/%s/records/%d", domain, recordID)); err != nil {
		return fmt.Errorf("failed delete record (binarylane): %w", err)
	}
	return nil
}

func (c *binarylaneProvider) modifyRecord(domain string, recordID int64, rec requestParams) error {
	if _, err := c.put(fmt.Sprintf("/domains/%s/records/%d", domain, recordID), rec); err != nil {
		return fmt.Errorf("failed update record (binarylane): %w", err)
	}
	return nil
}

func (c *binarylaneProvider) getRecords(domain string) ([]domainRecord, error) {
	bodyString, err := c.get("/domains/" + domain + "/records")
	if err != nil {
		return nil, fmt.Errorf("failed fetching record list from binarylane: %w", err)
	}

	var dr recordResponse
	err = json.Unmarshal(bodyString, &dr)
	if err != nil {
		return nil, fmt.Errorf("failed parsing record list from binarylane: %w", err)
	}

	// FIXME: handle paging

	var records []domainRecord
	for _, rec := range dr.Records {
		// if rec.Name == domain && rec.Type == "NS" {
		// 	continue
		// }
		records = append(records, rec)
	}
	return records, nil
}

func (c *binarylaneProvider) getNameservers(domain string) ([]string, error) {
	fmt.Printf("getNameservers\n")
	bodyString, err := c.get("/domain/" + domain)
	if err != nil {
		return nil, fmt.Errorf("failed fetching nameserver list from binarylane: %w", err)
	}

	var ns nsResponse
	err = json.Unmarshal(bodyString, &ns)
	if err != nil {
		return nil, fmt.Errorf("failed parsing nameserver list from binarylane: %w", err)
	}

	sort.Strings(ns.Nameservers)

	var nameservers []string
	for _, nameserver := range ns.Nameservers {
		// Remove the trailing dot only if it exists.
		// This provider seems to add the trailing dot to some domains but not others.
		// The .DE domains seem to always include the dot, others don't.
		nameservers = append(nameservers, strings.TrimSuffix(nameserver, "."))
	}
	return nameservers, nil
}

func (c *binarylaneProvider) updateNameservers(ns []string, domain string) error {
	params := requestParams{}
	params["ns"] = ns
	if _, err := c.post("/domain/updateNs/"+domain, params); err != nil {
		return fmt.Errorf("failed NS update (binarylane): %w", err)
	}
	return nil
}

func (c *binarylaneProvider) listAllDomains() ([]string, error) {
	bodyString, err := c.get("/domains")
	if err != nil {
		return nil, fmt.Errorf("failed listing all domains from binarylane: %w", err)
	}

	var dlr domainListResponse
	err = json.Unmarshal(bodyString, &dlr)
	if err != nil {
		return nil, fmt.Errorf("failed parsing domain list from binarylane: %w", err)
	}

	// FIXME: handle paging

	var domains []string
	for _, domain := range dlr.Domains {
		domains = append(domains, domain.Domain)
	}
	sort.Strings(domains)
	return domains, nil
}
