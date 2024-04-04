// Copyright (c) Facebook, Inc. and its affiliates.
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
// See the License for the specific language governing permissions andT47981963
// limitations under the License.

package schema

import (
	"errors"
	"fmt"
	"time"

	nvd "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)

// TODO: move this file to its own package in the future, to implement a common
// API for all providers (hence the "Providers" namespace). We will need to add
// missing features to support all providers.

const (
	providersDataFormat  = "MITRE"
	providersDataType    = "CVE"
	providersDataLang    = "en"
	providersDataVersion = "4.0"
	providersTimeLayout  = "2006-01-02T15:04Z"
)

// ProvidersItem captures the top-level CVE information for a vendor.
type ProvidersItem struct {
	Vendor           string
	ID               string
	Description      string
	CWEs             []string
	References       *ProvidersReferences
	Configuration    *ProvidersConfiguration
	CVSS2            *ProvidersCVSS
	CVSS3            *ProvidersCVSS
	LastModifiedDate *time.Time
	PublishedDate    *time.Time
}

// ProvidersCVSS is used to store CVSS2 and CVSS3 data.
type ProvidersCVSS struct {
	BaseScore     float64
	TemporalScore float64
	Vector        string
}

// ProvidersReferences hold data related to the thread.
type ProvidersReferences struct {
	referenceData []*nvd.CVEAPIJSONReference
}

// ProvidersConfiguration captures what specific software versions are vulnerable.
type ProvidersConfiguration struct {
	Nodes []*ProvidersNode
}

// ProvidersNode holds a set of matches, any positive match being able to
// configure a CVE. If conditional matches are present as well, then at least
// one conditional match should also be positive to configure a CVE.
type ProvidersNode struct {
	matches            []*nvd.NVDCVEFeedJSON10DefCPEMatch
	conditionalMatches []*nvd.NVDCVEFeedJSON10DefCPEMatch
}

// ProvidersMatch represents software versions that match a CPE.
type ProvidersMatch struct {
	CPE22URI              string
	CPE23URI              string
	VersionStartExcluding string
	VersionStartIncluding string
	VersionEndExcluding   string
	VersionEndIncluding   string
	Vulnerable            bool
}

// ProvidersConvertStrTime takes a time layout and a string representing time in that
// layout and converts it to a Time type. If the string is empty nil is
// returned.
func ProvidersConvertStrTime(layout, strTime string) (*time.Time, error) {
	if strTime == "" {
		return nil, nil
	}

	t, err := time.Parse(layout, strTime)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func providersConvertTime(t *time.Time) string {
	if t == nil {
		return ""
	}

	return t.Format(providersTimeLayout)
}

// ProvidersNewItem creates a vendor item.
func ProvidersNewItem(item *ProvidersItem) (*nvd.NVDCVEAPIFeedJSONDefCVEItem, error) {
	if err := item.validate(); err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}

	return &nvd.NVDCVEAPIFeedJSONDefCVEItem{
		Id: item.ID,
		SourceIdentifier: item.Vendor,
		Descriptions: &nvd.CVEAPIJSONDescription{
			DescriptionData: []*nvd.CVEJSON40LangString{
				{
					Lang:  providersDataLang,
					Value: item.Description,
				},
			},
		},
		Weaknesses: item.problemType(),
		References:  item.references(),
		Configurations: item.Configuration.convertToNVD(),
		Metrics: &nvd.NVDCVEAPIFeedJSONDefMetrics{
			CVSSMetricV2: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV2{
				{
					CVSSData: item.cvssV20(),
				},
			},
			CVSSMetricV30: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV31{
				{
					CVSSData: item.cvssV30(),
				},
			},
		},
		LastModified: providersConvertTime(item.LastModifiedDate),
		Published:    providersConvertTime(item.PublishedDate),
	}, nil
}

// validate will return an error if any mandatory fields are missing.
func (item *ProvidersItem) validate() error {
	if item.ID == "" || item.Vendor == "" || item.Description == "" {
		return errors.New("id, vendor and description can't be empty")
	}

	if item.Configuration == nil {
		return errors.New("configuration can't be nil")
	}

	return nil
}

func (item *ProvidersItem) cvssV20() *nvd.CVSSData {
	if item.CVSS2 == nil {
		return nil
	}

	return &nvd.CVSSData{
		BaseScore:     item.CVSS2.BaseScore,
		TemporalScore: item.CVSS2.TemporalScore,
		VectorString:  item.CVSS2.Vector,
	}
}

func (item *ProvidersItem) cvssV30() *nvd.CVSSData {
	if item.CVSS3 == nil {
		return nil
	}

	return &nvd.CVSSData{
		BaseScore:     item.CVSS3.BaseScore,
		TemporalScore: item.CVSS3.TemporalScore,
		VectorString:  item.CVSS3.Vector,
	}
}

func (item *ProvidersItem) references() []*nvd.CVEAPIJSONReference {
	if item.References == nil || item.References.referenceData == nil {
		return nil
	}

	return item.References.referenceData
}

func (item *ProvidersItem) problemType() []*nvd.CVEAPIJSONWeakness {
	if item.CWEs == nil {
		return nil
	}

	var weaknesses []*nvd.CVEJSON40LangString

	for _, cwe := range item.CWEs {
		weaknesses = append(weaknesses, &nvd.CVEJSON40LangString{
			Lang:  providersDataLang,
			Value: cwe,
		})
	}

	return []*nvd.CVEAPIJSONWeakness{
		{
			Source: "",
			Type: "",
			Description: weaknesses,
		},
	}
}

// ProvidersNewReferences creates a ProvidersReferences.
func ProvidersNewReferences() *ProvidersReferences {
	return &ProvidersReferences{}
}

// Add adds a new reference to the references.
func (r *ProvidersReferences) Add(name, url string) {
	r.referenceData = append(r.referenceData, &nvd.CVEAPIJSONReference{
		URL:  url,
	})
}

// ProvidersNewConfiguration creates a ProvidersConfiguration.
func ProvidersNewConfiguration() *ProvidersConfiguration {
	return &ProvidersConfiguration{
		Nodes: []*ProvidersNode{},
	}
}

func (c *ProvidersConfiguration) convertToNVD() []*nvd.NVDCVEAPIFeedJSONDefNode {
	var nvdNodes []*nvd.NVDCVEAPIFeedJSONDefNode

	for _, node := range c.Nodes {
		nvdNode := &nvd.NVDCVEAPIFeedJSONDefNode{}

		if len(node.conditionalMatches) > 0 {
			// nvdNode.Operator = "AND"
			// nvdNode.Children = []*nvd.NVDCVEAPIFeedJSONDefNode{
			// 	&nvd.NVDCVEAPIFeedJSONDefNode{
			// 		Operator: "OR",
			// 		CPEMatch: node.matches,
			// 	},
			// 	&nvd.NVDCVEAPIFeedJSONDefNode{
			// 		Operator: "OR",
			// 		CPEMatch: node.conditionalMatches,
			// 	},
			// }
		} else {
			nvdNode.Operator = "OR"
			nvdNode.CPEMatch = node.matches
		}

		nvdNodes = append(nvdNodes, nvdNode)
	}

	return nvdNodes
}

// NewNode creates a Node in the ProvidersConfiguration
func (c *ProvidersConfiguration) NewNode() *ProvidersNode {
	node := &ProvidersNode{
		matches:            []*nvd.NVDCVEFeedJSON10DefCPEMatch{},
		conditionalMatches: []*nvd.NVDCVEFeedJSON10DefCPEMatch{},
	}

	c.Nodes = append(c.Nodes, node)

	return node
}

// AddMatch adds a ProvidersMatch to a ProvidersNode.
func (node *ProvidersNode) AddMatch(m *ProvidersMatch) {
	node.matches = append(node.matches, m.convertToNVD())
}

// AddConditionalMatch adds a ProvidersMatch to a ProvidersNode.
func (node *ProvidersNode) AddConditionalMatch(m *ProvidersMatch) {
	node.conditionalMatches = append(node.conditionalMatches, m.convertToNVD())
}

// ProvidersNewMatch creates a ProvidersMatch.
func ProvidersNewMatch(cpe22uri, cpe23uri string, vulnerable bool) *ProvidersMatch {
	return &ProvidersMatch{
		CPE22URI:   cpe22uri,
		CPE23URI:   cpe23uri,
		Vulnerable: vulnerable,
	}
}

func (m *ProvidersMatch) convertToNVD() *nvd.NVDCVEFeedJSON10DefCPEMatch {
	return &nvd.NVDCVEFeedJSON10DefCPEMatch{
		MatchCriteriaId:              m.CPE22URI,
		Criteria:              m.CPE23URI,
		VersionStartExcluding: m.VersionStartExcluding,
		VersionStartIncluding: m.VersionStartIncluding,
		VersionEndExcluding:   m.VersionEndExcluding,
		VersionEndIncluding:   m.VersionEndIncluding,
		Vulnerable:            m.Vulnerable,
	}
}

// AddVersionStart adds the starting version to a Match, along with
// whether that version is included or excluded from the Match.
func (m *ProvidersMatch) AddVersionStart(version string, excluding bool) {
	if excluding {
		m.VersionStartExcluding = version
	} else {
		m.VersionStartIncluding = version
	}
}

// AddVersionEnd adds the ending version to a Match, along with
// whether that version is included or excluded from the Match.
func (m *ProvidersMatch) AddVersionEnd(version string, excluding bool) {
	if excluding {
		m.VersionEndExcluding = version
	} else {
		m.VersionEndIncluding = version
	}
}
