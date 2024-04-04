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
	"time"

	"github.com/facebookincubator/flog"
	nvd "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/wfn"
)

const (
	cveDataVersion = "4.0"
	timeLayout     = "2006-01-02T15:04:05Z"
)

func (item *Vulnerability) Convert() (*nvd.NVDCVEAPIFeedJSONDefCVEItem, error) {
	lastModifiedDate, err := convertTime(item.VulndbLastModified)
	if err != nil {
		return nil, fmt.Errorf("can't convert last modified date: %v", err)
	}
	publishedDate, err := convertTime(item.VulndbPublishedDate)
	if err != nil {
		return nil, fmt.Errorf("can't convert published date: %v", err)
	}
	impact, err := item.makeImpact()
	if err != nil {
		return nil, fmt.Errorf("can't create impact: %v", err)
	}

	nvdItem := nvd.NVDCVEAPIFeedJSONDefCVEItem{
		Id: item.ID(),
		SourceIdentifier: "rbs",
		Descriptions: &nvd.CVEAPIJSONDescription{
			DescriptionData: []*nvd.CVEJSON40LangString{
				{Lang: "en", Value: item.Title},
				{Lang: "en", Value: item.Description},
			},
		},
		References:  item.makeReferences(),
		Configurations:   item.makeConfigurations(),
		Metrics:     impact,
		Weaknesses: []*nvd.CVEAPIJSONWeakness{},
		LastModified: lastModifiedDate,
		Published:    publishedDate,
	}

	addNVDData(&nvdItem, item.NVDAdditionalInfo)

	return &nvdItem, nil
}

func (item *Vulnerability) ID() string {
	return fmt.Sprintf("rbs-%d", item.VulndbID)
}

func (item *Vulnerability) makeReferences() []*nvd.CVEAPIJSONReference {
	if len(item.ExtReferences) == 0 {
		return nil
	}

	var refsData []*nvd.CVEAPIJSONReference

	for _, ref := range item.ExtReferences {
		refsData = append(refsData, &nvd.CVEAPIJSONReference{
			URL:  ref.Value,
		})
	}

	return refsData
}

func (item *Vulnerability) makeConfigurations()  []*nvd.NVDCVEAPIFeedJSONDefNode {
	var matches []*nvd.NVDCVEFeedJSON10DefCPEMatch

	for _, vendor := range item.Vendors {
		for _, product := range vendor.Products {
			for _, version := range product.Versions {
				if version.Affected == "false" {
					continue
				}
				for _, cpe := range version.CPEs {
					c, err := normalizeCPE(cpe.CPE)
					if err != nil {
						flog.Errorf("couldn't normalize cpe %q: %v", cpe.CPE, err)
						continue
					}
					match := &nvd.NVDCVEFeedJSON10DefCPEMatch{
						Criteria:   c,
						Vulnerable: true,
					}
					matches = append(matches, match)
				}
			}
		}
	}

	conf := []*nvd.NVDCVEAPIFeedJSONDefNode{
		{
			CPEMatch: matches,
			Operator: "OR",
		},
	}

	return conf
}

func (item *Vulnerability) makeImpact() (*nvd.NVDCVEAPIFeedJSONDefMetrics, error) {
	// TODO they don't have cvss vectors. they do have parts of it so we could construct them
	// using our library nvdtools/cvss{2,3}/...

	l2 := len(item.CVSSMetrics)
	l3 := len(item.CVSS3Metrics)

	if l2 == 0 && l3 == 0 {
		return nil, fmt.Errorf("no cvss metrics found")
	}

	var cvssv2 *nvd.CVSSData
	if l2 != 0 {
		cvssv2 = &nvd.CVSSData{BaseScore: item.CVSSMetrics[l2-1].Score}
	}

	var cvssv3 *nvd.CVSSData
	if l3 != 0 {
		cvssv3 = &nvd.CVSSData{BaseScore: item.CVSS3Metrics[l3-1].Score}
	}

	impact := nvd.NVDCVEAPIFeedJSONDefMetrics{
		CVSSMetricV2: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV2{
			{
				CVSSData: cvssv2,
			},
		},
		CVSSMetricV30: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV31{
			{
				CVSSData: cvssv3,
			},
		},
	}

	return &impact, nil
}

func convertTime(rbsTime string) (string, error) {
	if rbsTime == "" { // handle no time
		return "", nil
	}
	t, err := time.Parse(timeLayout, rbsTime)
	if err != nil { // should be parsable
		return "", err
	}
	return t.Format(nvd.TimeLayout), nil
}

func normalizeCPE(cpe string) (string, error) {
	attrs, err := wfn.UnbindFmtString(cpe)
	if err != nil {
		return "", fmt.Errorf("can't unbind CPE URI: %v", err)
	}
	if attrs.Version == "Unspecified" {
		attrs.Version = wfn.Any
	}
	return attrs.BindToFmtString(), nil
}

func addNVDData(nvdItem *nvd.NVDCVEAPIFeedJSONDefCVEItem, additional []*NVDAdditionalInfo) {
	addRef := func(_, url string) {
		nvdItem.References = append(
			nvdItem.References,
			&nvd.CVEAPIJSONReference{
				URL:  url,
			},
		)
	}

	addCWE := func(cwe string) {
		nvdItem.Weaknesses = append(
			nvdItem.Weaknesses,
			&nvd.CVEAPIJSONWeakness{
				Source: "",
				Type: "",
				Description: []*nvd.CVEJSON40LangString{
					{Lang: "en", Value: cwe},
				},				
			},
		)
	}

	for _, add := range additional {
		addRef(add.CVEID, "")
		for _, ref := range add.References {
			addRef(ref.Name, ref.URL)
		}
		addCWE(add.CWEID)
	}
}
