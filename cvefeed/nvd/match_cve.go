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
// See the License for the specific language governing permissions and
// limitations under the License.

package nvd

import (
	"regexp"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/wfn"
)

var cveRegex = regexp.MustCompile("CVE-[0-9]{4}-[0-9]{4,}")

func ToVuln(cve *schema.NVDCVEAPIFeedJSONDefCVEItem) *Vuln {
	vuln := &Vuln{
		cveItem: cve,
	}

	var ms []wfn.Matcher
	for _, node := range cve.Configurations.Nodes {
		if node != nil {
			if m, err := nodeMatcher(vuln.ID(), node); err == nil {
				ms = append(ms, m)
			}
		}
	}
	vuln.Matcher = wfn.MatchAny(ms...)

	return vuln
}

// Vuln implements the cvefeed.Vuln interface
type Vuln struct {
	cveItem *schema.NVDCVEAPIFeedJSONDefCVEItem
	wfn.Matcher
}

// Schema returns the underlying schema of the Vuln
func (v *Vuln) Schema() *schema.NVDCVEAPIFeedJSONDefCVEItem {
	return v.cveItem
}

// ID is a part of the cvefeed.Vuln Interface
func (v *Vuln) ID() string {
	if v == nil || v.cveItem == nil {
		return ""
	}
	return v.cveItem.Id
}

// CVEs is a part of the cvefeed.Vuln Interface
func (v *Vuln) CVEs() []string {
	if v == nil || v.cveItem == nil {
		return nil
	}

	var cves []string

	addMatch := func(s string) bool {
		if cve := cveRegex.FindString(s); cve != "" {
			cves = append(cves, cve)
			return true
		}
		return false
	}

	// check if ID contains CVE
	addMatch(v.ID())

	// add references
	if refs := v.cveItem.References; refs != nil {
		for _, refd := range refs {
			if refd != nil {
				addMatch(refd.URL)
			}
		}
	}

	return unique(cves)
}

// CWEs is a part of the cvefeed.Vuln Interface
func (v *Vuln) CWEs() []string {
	if v == nil || v.cveItem == nil || v.cveItem.Weaknesses == nil {
		return nil
	}

	var cwes []string

	for _, weakness := range v.cveItem.Weaknesses {
		if weakness != nil {
			for _, desc := range weakness.Description.DescriptionData {
				if desc != nil {
					if desc.Lang == "en" {
						cwes = append(cwes, desc.Value)
					}
				}
			}
		}
	}

	return unique(cwes)
}

// CVSSv2BaseScore is a part of the cvefeed.Vuln Interface
func (v *Vuln) CVSSv2BaseScore() float64 {
	if c := v.cvssv2(); c != nil {
		return c.BaseScore
	}
	return 0.0
}

// CVSSv2Vector is a part of the cvefeed.Vuln Interface
func (v *Vuln) CVSSv2Vector() string {
	if c := v.cvssv2(); c != nil {
		return c.VectorString
	}
	return ""
}

// CVSSv3BaseScore is a part of the cvefeed.Vuln Interface
func (v *Vuln) CVSSv3BaseScore() float64 {
	if c := v.cvssv3(); c != nil {
		return c.BaseScore
	}
	return 0.0
}

// CVSSv3Vector is a part of the cvefeed.Vuln Interface
func (v *Vuln) CVSSv3Vector() string {
	if c := v.cvssv3(); c != nil {
		return c.VectorString
	}
	return ""
}

// unique returns unique strings from input
func unique(ss []string) []string {
	var us []string
	set := make(map[string]bool)
	for _, s := range ss {
		if !set[s] {
			us = append(us, s)
		}
		set[s] = true
	}
	return us
}

// just a helper to return the cvssv2 data
func (v *Vuln) cvssv2() *schema.CVSSData {
	if v == nil || v.cveItem == nil || v.cveItem.Metrics == nil || v.cveItem.Metrics.CVSSMetricV2.CVSSData == nil {
		return nil
	}
	return v.cveItem.Metrics.CVSSMetricV2.CVSSData
}

// just a helper to return the cvssv3 data
func (v *Vuln) cvssv3() *schema.CVSSData {
	if v == nil || v.cveItem == nil || v.cveItem.Metrics == nil || v.cveItem.Metrics.CVSSMetricV30.CVSSData == nil {
		return nil
	}
	return v.cveItem.Metrics.CVSSMetricV30.CVSSData
}

// just a helper to return the cvssv31 data
func (v *Vuln) cvssv31() *schema.CVSSData {
	if v == nil || v.cveItem == nil || v.cveItem.Metrics == nil || v.cveItem.Metrics.CVSSMetricV31.CVSSData == nil {
		return nil
	}
	return v.cveItem.Metrics.CVSSMetricV31.CVSSData
}