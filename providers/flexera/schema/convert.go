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

	nvd "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)

// Convert converts  advisories to NVD format
func (item *Advisory) Convert() (*nvd.NVDCVEAPIFeedJSONDefCVEItem, error) {
	if item.Products == nil {
		return nil, fmt.Errorf("no products associated with advisory")
	}

	var cpes []string
	for _, product := range item.Products {
		if productCPEs, err := findCPEs(product); err == nil {
			cpes = append(cpes, productCPEs...)
		}
	}
	if len(cpes) == 0 {
		return nil, fmt.Errorf("no cpes associated with advisory")
	}

	lastModifiedDate, err := convertTime(item.ModifiedDate)
	if err != nil {
		return nil, err
	}

	publishedDate, err := convertTime(item.Released)
	if err != nil {
		return nil, err
	}

	return &nvd.NVDCVEAPIFeedJSONDefCVEItem{
		Id: item.ID(),
		SourceIdentifier: "flexera",
		Descriptions: &nvd.CVEAPIJSONDescription{
			DescriptionData: []*nvd.CVEJSON40LangString{
				{Lang: "en", Value: item.Description},
			},
		},
		Configurations:   	makeConfigurations(cpes),
		References: 		item.makeReferences(),
		Metrics:           item.makeImpact(),
		LastModified: 	   lastModifiedDate,
		Published:    	   publishedDate,
	}, nil
}

func (item *Advisory) ID() string {
	return "flexera-" + item.AdvisoryIdentifier
}

func (item *Advisory) makeReferences() []*nvd.CVEAPIJSONReference {
	var refsData []*nvd.CVEAPIJSONReference
	addRef := func(_, url string) {
		refsData = append(refsData, &nvd.CVEAPIJSONReference{
			URL:  url,
		})
	}

	if item.References != nil {
		for _, ref := range item.References {
			addRef(ref.Description, ref.URL)
		}
	}

	if item.Vulnerabilities != nil {
		for _, vuln := range item.Vulnerabilities {
			addRef(vuln.Cve, "")
		}
	}

	return refsData
}

func makeConfigurations(cpes []string) []*nvd.NVDCVEAPIFeedJSONDefNode {
	matches := make([]*nvd.NVDCVEFeedJSON10DefCPEMatch, len(cpes))
	for i, cpe := range cpes {
		matches[i] = &nvd.NVDCVEFeedJSON10DefCPEMatch{
			MatchCriteriaId:   cpe,
			Vulnerable: true,
		}
	}

	return []*nvd.NVDCVEAPIFeedJSONDefNode{
		{
			CPEMatch: matches,
			Operator: "OR",
		},
	}
}

func (item *Advisory) makeImpact() *nvd.NVDCVEAPIFeedJSONDefMetrics {
	var cvssv2 nvd.CVSSData
	if item.CvssInfo != nil {
		cvssv2.BaseScore = item.CvssInfo.BaseScore
		cvssv2.VectorString = item.CvssInfo.Vector
	}
	var cvssv3 nvd.CVSSData
	if item.Cvss3Info != nil {
		cvssv3.BaseScore = item.Cvss3Info.BaseScore
		cvssv3.VectorString = item.Cvss3Info.Vector
	}

	return &nvd.NVDCVEAPIFeedJSONDefMetrics{
		CVSSMetricV2: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV2{
			{
				CVSSData: &cvssv2,
			},
		},
		CVSSMetricV30: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV31{
			{
				CVSSData: &cvssv3,
			},
		},
	}
}
