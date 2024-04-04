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
	nvd "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"

	"github.com/pkg/errors"
)

// Convert implements runner.Convertible interface
func (item *Vulnerability) Convert() (*nvd.NVDCVEAPIFeedJSONDefCVEItem, error) {
	lastModifiedDate, err := convertTime(item.LastModified)
	if err != nil {
		return nil, errors.Wrap(err, "can't convert last modified date")
	}
	publishedDate, err := convertTime(item.LastPublished)
	if err != nil {
		return nil, errors.Wrap(err, "can't convert published date")
	}

	configurations, err := item.makeConfigurations()
	if err != nil {
		return nil, errors.Wrap(err, "can't create configurations")
	}

	return &nvd.NVDCVEAPIFeedJSONDefCVEItem{
		Id:       item.ID(),
		SourceIdentifier: "idefense",
		Descriptions: &nvd.CVEAPIJSONDescription{
			DescriptionData: []*nvd.CVEJSON40LangString{
				{Lang: "en", Value: item.Description},
			},
		},
		Configurations: configurations,
		Metrics: &nvd.NVDCVEAPIFeedJSONDefMetrics{
			CVSSMetricV2: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV2{
				{
					CVSSData: &nvd.CVSSData{
						BaseScore:     item.Cvss2BaseScore,
						TemporalScore: item.Cvss2TemporalScore,
						VectorString:  item.Cvss2,
					},
				},
			},
			CVSSMetricV30: []*nvd.NVDCVEAPIFeedJSONDefImpactBaseMetricV31{
				{
					CVSSData: &nvd.CVSSData{
						BaseScore:     item.Cvss3BaseScore,
						TemporalScore: item.Cvss3TemporalScore,
						VectorString:  item.Cvss3,
					},
				},
			},
		},
		Weaknesses: []*nvd.CVEAPIJSONWeakness{
			{
				Source: "",
				Type: "",
				Description: []*nvd.CVEJSON40LangString{
						{Lang: "en", Value: item.Cwe},
				},
			},
		},
		References: item.makeReferences(),
		LastModified: lastModifiedDate,
		Published:    publishedDate,
	}, nil
}

func (item *Vulnerability) ID() string {
	return "idefense-" + item.Key
}

func (item *Vulnerability) makeReferences() []*nvd.CVEAPIJSONReference {
	if len(item.SourcesExternal) == 0 {
		return nil
	}

	var refsData []*nvd.CVEAPIJSONReference
	addRef := func(_, url string) {
		refsData = append(refsData, &nvd.CVEAPIJSONReference{
			URL:  url,
		})
	}

	for _, source := range item.SourcesExternal {
		addRef(source.Name, source.URL)
	}
	if item.AlsoIdentifies != nil {
		for _, vuln := range item.AlsoIdentifies.Vulnerability {
			addRef(vuln.Key, "")
		}
	}
	for _, poc := range item.Pocs {
		addRef(poc.PocName, poc.URL)
	}
	for _, fix := range item.VendorFixExternal {
		addRef(fix.ID, fix.URL)
	}

	return refsData
}

func (item *Vulnerability) makeConfigurations() ([]*nvd.NVDCVEAPIFeedJSONDefNode, error) {
	configs := item.findConfigurations()
	if len(configs) == 0 {
		return nil, errors.New("unable to find any configurations in data")
	}

	var matches []*nvd.NVDCVEFeedJSON10DefCPEMatch
	for _, cfg := range configs {
		for _, affected := range cfg.Affected {
			match := &nvd.NVDCVEFeedJSON10DefCPEMatch{
				Criteria:   cfg.Cpe23Uri,
				Vulnerable: true,
			}

			// determine version ranges
			if cfg.HasFixedBy {
				if affected.Prior {
					match.VersionEndExcluding = cfg.FixedByVersion
				} else {
					match.VersionStartIncluding = affected.Version
					match.VersionEndExcluding = cfg.FixedByVersion
				}
			} else {
				if !affected.Prior {
					match.VersionStartIncluding = affected.Version
				}
			}
			matches = append(matches, match)
		}
	}

	v := []*nvd.NVDCVEAPIFeedJSONDefNode{
		{
			CPEMatch: matches,
			Operator: "OR",
		},
	}

	return v, nil
}
