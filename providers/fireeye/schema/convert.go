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
	"strings"

	nvd "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)


func (item *Vulnerability) Convert() (*nvd.NVDCVEAPIFeedJSONDefCVEItem, error) {
	nvdItem := nvd.NVDCVEAPIFeedJSONDefCVEItem{
		Id: item.ID(),
		SourceIdentifier: "fireeye",
		Descriptions: &nvd.CVEAPIJSONDescription{
			DescriptionData: []*nvd.CVEJSON40LangString{
				{Lang: "en", Value: item.Title},
			},
		},
		Configurations: item.makeConfigurations(),
		References: item.makeReferences(),
		Metrics: &nvd.NVDCVEAPIFeedJSONDefMetrics{
			CVSSMetricV2: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV2{
				{
					CVSSData: &nvd.CVSSData{
						BaseScore:     extractCVSSBaseScore(item),
						TemporalScore: extractCVSSTemporalScore(item),
						VectorString:  extractCVSSVectorString(item),
					},
				},
			},
		},
		LastModified: convertTime(item.PublishDate),
		Published:    convertTime(item.Version1PublishDate),
	}

	return &nvdItem, nil
}

func (item *Vulnerability) ID() string {
	return "fireeye-" + item.ReportID
}

func (item *Vulnerability) makeReferences() []*nvd.CVEAPIJSONReference {
	var refsData []*nvd.CVEAPIJSONReference
	addRef := func(_, url string) {
		refsData = append(refsData, &nvd.CVEAPIJSONReference{
			URL:  url,
		})
	}

	addRef("FireEye report API link", item.ReportLink)
	addRef("FireEye web link", item.WebLink)
	for _, cve := range item.CVEIds {
		for _, cveid := range strings.Split(cve, ",") {
			addRef(cveid, "")
		}
	}

	return refsData
}

func (item *Vulnerability) makeConfigurations() []*nvd.NVDCVEAPIFeedJSONDefNode {
	var matches []*nvd.NVDCVEFeedJSON10DefCPEMatch
	for _, cpe := range extractCPEs(item) {
		matches = append(matches, &nvd.NVDCVEFeedJSON10DefCPEMatch{
			Criteria:   cpe,
			Vulnerable: true,
		})
	}

	return []*nvd.NVDCVEAPIFeedJSONDefNode{
		{
			CPEMatch: matches,
			Operator: "OR",
		},
	}
}
