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

package schema

import (
	"fmt"
	"strconv"
	"strings"

	nvd "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)

const (
	cveVersion = "4.0"
)

func (cve *CVE) Convert() (*nvd.NVDCVEAPIFeedJSONDefCVEItem, error) {
	publishedDate, err := convertTime(cve.PublicDate)
	if err != nil {
		return nil, fmt.Errorf("unable to convert published date: %v", err)
	}
	configurations, err := cve.newConfigurations()
	if err != nil {
		return nil, fmt.Errorf("unable to construct configurations: %v", err)
	}
	impact, err := cve.newImpact()
	if err != nil {
		return nil, fmt.Errorf("unable to construct impact: %v", err)
	}

	item := nvd.NVDCVEAPIFeedJSONDefCVEItem{
		Id: cve.ID(),
		SourceIdentifier: "redhat",
		Descriptions: &nvd.CVEAPIJSONDescription{
			DescriptionData: []*nvd.CVEJSON40LangString{
				{
					Lang:  "en",
					Value: strings.Join(cve.Details, "\n"),
				},
			},
		},
		Configurations: configurations,
		References:  cve.newReferences(),
		Weaknesses: cve.newProblemType(),
		Metrics:    impact,
		Published:  publishedDate,
	}

	return &item, nil
}

func (cve *CVE) ID() string {
	return cve.Name
}

func (cve *CVE) newProblemType() []*nvd.CVEAPIJSONWeakness {
	cwes := findCWEs(cve.CWE)
	if len(cwes) == 0 {
		return nil
	}
	data := make([]*nvd.CVEAPIJSONWeakness, len(cwes))
	for i, cwe := range cwes {
		data[i] = &nvd.CVEAPIJSONWeakness{
			Source: "",
			Type: "",
			Description: []*nvd.CVEJSON40LangString{
				{
					Lang:  "en",
					Value: cwe,
				},
			},
		}
	}

	return data
}

func (cve *CVE) newReferences() []*nvd.CVEAPIJSONReference {
	if len(cve.References) == 0 {
		return nil
	}

	referenceData := make([]*nvd.CVEAPIJSONReference, len(cve.References))
	for i, ref := range cve.References {
		referenceData[i] = &nvd.CVEAPIJSONReference{URL: ref}
	}

	return referenceData
}

func (cve *CVE) newImpact() (*nvd.NVDCVEAPIFeedJSONDefMetrics, error) {
	if cve.CVSS == nil && cve.CVSS3 == nil {
		return nil, fmt.Errorf("cvss v2 nor cvss v3 is set in the cve")
	}

	impact := nvd.NVDCVEAPIFeedJSONDefMetrics{}

	if cve.CVSS != nil {
		score, err := strconv.ParseFloat(cve.CVSS.BaseScore, 64)
		if err != nil {
			return nil, fmt.Errorf("unable to parse cvss v2 base score: %v", err)
		}
		impact.CVSSMetricV2 = []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV2{
			{
				CVSSData: &nvd.CVSSData{
					BaseScore:    score,
					VectorString: cve.CVSS.Vector,
				},
			},
		}
	}

	if cve.CVSS3 != nil {
		score, err := strconv.ParseFloat(cve.CVSS3.BaseScore, 64)
		if err != nil {
			return nil, fmt.Errorf("unable to parse cvss v3 base score: %v", err)
		}
		impact.CVSSMetricV30 = []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV31{
			{
				CVSSData: &nvd.CVSSData{
					BaseScore:    score,
					VectorString: cve.CVSS3.Vector,
				},
			},
		}
	}

	return &impact, nil
}

// CPEs configuration, AKA the tricky part

func (cve *CVE) newConfigurations() ([]*nvd.NVDCVEAPIFeedJSONDefNode, error) {
	nodes := make([]*nvd.NVDCVEAPIFeedJSONDefNode, len(cve.AffectedRelease)+len(cve.PackageState))

	var err error

	for i, ar := range cve.AffectedRelease {
		if nodes[i], err = ar.createNode(); err != nil {
			return nil, fmt.Errorf("can't create node for affected release %d: %v", i, err)
		}
	}

	offset := len(cve.AffectedRelease)
	for i, ps := range cve.PackageState {
		if nodes[i+offset], err = ps.createNode(); err != nil {
			return nil, fmt.Errorf("can't create node for package state %d: %v", i, err)
		}
	}
	return nodes, nil
}

func (ar *AffectedRelease) createNode() (*nvd.NVDCVEAPIFeedJSONDefNode, error) {
	node := nvd.NVDCVEAPIFeedJSONDefNode{
		Operator: "AND",
		CPEMatch: []*nvd.NVDCVEFeedJSON10DefCPEMatch{
			{
				MatchCriteriaId:   ar.CPE,
				Vulnerable: false,
			},
		},
	}

	if ar.Package != "" {
		pkgAttrs, err := package2wfn(ar.Package)
		if err != nil {
			return nil, fmt.Errorf("can't create wfn from package: %v", err)
		}

		node.CPEMatch = append(node.CPEMatch, &nvd.NVDCVEFeedJSON10DefCPEMatch{
			MatchCriteriaId:   pkgAttrs.BindToURI(),
			Criteria:   pkgAttrs.BindToFmtString(),
			Vulnerable: false,
		})
	}

	return &node, nil
}

func (ps *PackageState) createNode() (*nvd.NVDCVEAPIFeedJSONDefNode, error) {
	pkgAttrs, err := packageName2wfn(ps.PackageName)
	if err != nil {
		return nil, fmt.Errorf("can't create wfn from package name: %v", err)
	}

	node := nvd.NVDCVEAPIFeedJSONDefNode{
		Operator: "AND",
		CPEMatch: []*nvd.NVDCVEFeedJSON10DefCPEMatch{
			// package
			{
				MatchCriteriaId:   pkgAttrs.BindToURI(),
				Criteria:   pkgAttrs.BindToFmtString(),
				Vulnerable: !IsFixed(ps.FixState),
			},
			// distribution
			{
				MatchCriteriaId:   ps.CPE,
				Vulnerable: false,
			},
		},
	}

	return &node, nil
}
