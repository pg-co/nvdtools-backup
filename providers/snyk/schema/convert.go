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
	"github.com/facebookincubator/flog"
	nvd "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/wfn"
)


func (advisory *Advisory) Convert() (*nvd.NVDCVEAPIFeedJSONDefCVEItem, error) {
	nvdItem := nvd.NVDCVEAPIFeedJSONDefCVEItem{
		Id: advisory.ID(),
		SourceIdentifier: "snyk.io",
		Descriptions: &nvd.CVEAPIJSONDescription{
			DescriptionData: []*nvd.CVEJSON40LangString{
				{
					Lang:  "en",
					Value: advisory.Description,
				},
			},
		},
		Configurations: advisory.newConfigurations(),
		Metrics: &nvd.NVDCVEAPIFeedJSONDefMetrics{
			CVSSMetricV30: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV31{
				{
					CVSSData: &nvd.CVSSData{
						BaseScore:    advisory.CVSSV3BaseScore,
						VectorString: advisory.CVSSV3Vector,
					},
				},
			},
		},
		Weaknesses: advisory.newProblemType(),
		References:  advisory.newReferences(),
		LastModified: snykTimeToNVD(advisory.Modified),
		Published:    snykTimeToNVD(advisory.Published),
	}

	return &nvdItem, nil
}

func (advisory *Advisory) ID() string {
	return advisory.SnykID
}

func (advisory *Advisory) newProblemType() []*nvd.CVEAPIJSONWeakness {
	if len(advisory.CweIDs) == 0 {
		return nil
	}

	w := &nvd.CVEAPIJSONWeakness{
		Source: "",
		Type: "",
		Description: make([]*nvd.CVEJSON40LangString, len(advisory.CweIDs)),
	}

	for i, cwe := range advisory.CweIDs {
		w.Description[i] = &nvd.CVEJSON40LangString{
			Lang:  "en",
			Value: cwe,
		}
	}
	return []*nvd.CVEAPIJSONWeakness{
		w,
	}
}

func (advisory *Advisory) newReferences() []*nvd.CVEAPIJSONReference {
	if len(advisory.References) == 0 {
		return nil
	}
	nrefs := 1 + len(advisory.References) + len(advisory.CveIDs)
	refs := &nvd.CVEAPIJSONReferences{
		ReferenceData: make([]*nvd.CVEAPIJSONReference, 0, nrefs),
	}
	addRef := func(_, url string) {
		refs.ReferenceData = append(refs.ReferenceData, &nvd.CVEAPIJSONReference{
			URL:  url,
		})
	}
	if advisory.Title != "" && advisory.SnykAdvisoryURL != "" {
		addRef(advisory.Title, advisory.SnykAdvisoryURL)
	}
	for _, ref := range advisory.References {
		addRef(ref.Title, ref.URL)
	}
	for _, cve := range advisory.CveIDs {
		addRef(cve, "")
	}
	return refs.ReferenceData
}

func (advisory *Advisory) newConfigurations() []*nvd.NVDCVEAPIFeedJSONDefNode {
	nodes := []*nvd.NVDCVEAPIFeedJSONDefNode{
		{
			Operator: "OR",
		},
	}
	var err error
	var product string
	if product, err = wfn.WFNize(advisory.Package); err != nil {
		flog.Errorf("can't wfnize %q\n", advisory.Package)
		product = advisory.Package
	}
	cpe := wfn.Attributes{Part: "a", Product: product}
	// cpe22URI := cpe.BindToURI()
	cpe23URI := cpe.BindToFmtString()
	for _, versions := range advisory.VulnerableVersions {
		vRanges, err := parseVersionRange(versions)
		if err != nil {
			flog.Errorf("could not generate configuration for item %s, vulnerable ver %q: %v", advisory.SnykID, versions, err)
			continue
		}
		for _, vRange := range vRanges {
			node := &nvd.NVDCVEFeedJSON10DefCPEMatch{
				Criteria:              cpe23URI,
				VersionStartIncluding: vRange.minVerIncl,
				VersionStartExcluding: vRange.minVerExcl,
				VersionEndIncluding:   vRange.maxVerIncl,
				VersionEndExcluding:   vRange.maxVerExcl,
				Vulnerable:            true,
			}
			nodes[0].CPEMatch = append(nodes[0].CPEMatch, node)
		}
	}
	return nodes
}
