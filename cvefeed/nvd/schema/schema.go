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

// TimeLayout is the layout of NVD CVE timestamps.
const TimeLayout = "2006-01-02T15:04Z"

// NVDCVEFeedJSON10DefCPEName was auto-generated.
// CPE name.
type NVDCVEFeedJSON10DefCPEName struct {
	Cpe22Uri string `json:"cpe22Uri,omitempty"`
	Cpe23Uri string `json:"cpe23Uri"`
}

// NVDCVEFeedJSON10DefCPEMatch was auto-generated.
// CPE match string or range.
type NVDCVEFeedJSON10DefCPEMatch struct {
	// CPEName               []*NVDCVEFeedJSON10DefCPEName `json:"cpe_name,omitempty"`
	MatchCriteriaId              string                        `json:"matchCriteriaId,omitempty"`
	Criteria              string                        `json:"criteria"`
	VersionEndExcluding   string                        `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string                        `json:"versionEndIncluding,omitempty"`
	VersionStartExcluding string                        `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string                        `json:"versionStartIncluding,omitempty"`
	Vulnerable            bool                          `json:"vulnerable"`
}



// CVEJSON40CVEDataMeta was auto-generated.
type CVEJSON40CVEDataMeta struct {
	ASSIGNER string `json:"ASSIGNER"`
	ID       string `json:"ID"`
	STATE    string `json:"STATE,omitempty"`
}

// CVEJSON40ProductVersionVersionData was auto-generated.
type CVEJSON40ProductVersionVersionData struct {
	VersionAffected string `json:"version_affected,omitempty"`
	VersionValue    string `json:"version_value"`
}

// CVEJSON40ProductVersion was auto-generated.
type CVEJSON40ProductVersion struct {
	VersionData []*CVEJSON40ProductVersionVersionData `json:"version_data"`
}

// CVEJSON40Product was auto-generated.
type CVEJSON40Product struct {
	ProductName string                   `json:"product_name"`
	Version     *CVEJSON40ProductVersion `json:"version"`
}

// CVEJSON40AffectsVendorVendorDataProduct was auto-generated.
type CVEJSON40AffectsVendorVendorDataProduct struct {
	ProductData []*CVEJSON40Product `json:"product_data"`
}

// CVEJSON40AffectsVendorVendorData was auto-generated.
type CVEJSON40AffectsVendorVendorData struct {
	Product    *CVEJSON40AffectsVendorVendorDataProduct `json:"product"`
	VendorName string                                   `json:"vendor_name"`
}

// CVEJSON40AffectsVendor was auto-generated.
type CVEJSON40AffectsVendor struct {
	VendorData []*CVEJSON40AffectsVendorVendorData `json:"vendor_data"`
}

// CVEJSON40Affects was auto-generated.
type CVEJSON40Affects struct {
	Vendor *CVEJSON40AffectsVendor `json:"vendor"`
}

// CVEJSON40LangString was auto-generated.
type CVEJSON40LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// CVEJSON40ProblemtypeProblemtypeData was auto-generated.
type CVEJSON40ProblemtypeProblemtypeData struct {
	Description []*CVEJSON40LangString `json:"description"`
}

// CVEJSON40Problemtype was auto-generated.
type CVEJSON40Problemtype struct {
	ProblemtypeData []*CVEJSON40ProblemtypeProblemtypeData `json:"problemtype_data"`
}



// CVEJSON40 was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.0/CVE_JSON_4.0_min.schema


// CVSSData was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.0/cvss-v2.0.json
// type CVSSData struct {
// 	AccessComplexity           string  `json:"accessComplexity,omitempty"`
// 	AccessVector               string  `json:"accessVector,omitempty"`
// 	Authentication             string  `json:"authentication,omitempty"`
// 	AvailabilityImpact         string  `json:"availabilityImpact,omitempty"`
// 	AvailabilityRequirement    string  `json:"availabilityRequirement,omitempty"`
// 	BaseScore                  float64 `json:"baseScore"`
// 	CollateralDamagePotential  string  `json:"collateralDamagePotential,omitempty"`
// 	ConfidentialityImpact      string  `json:"confidentialityImpact,omitempty"`
// 	ConfidentialityRequirement string  `json:"confidentialityRequirement,omitempty"`
// 	EnvironmentalScore         float64 `json:"environmentalScore,omitempty"`
// 	Exploitability             string  `json:"exploitability,omitempty"`
// 	IntegrityImpact            string  `json:"integrityImpact,omitempty"`
// 	IntegrityRequirement       string  `json:"integrityRequirement,omitempty"`
// 	RemediationLevel           string  `json:"remediationLevel,omitempty"`
// 	ReportConfidence           string  `json:"reportConfidence,omitempty"`
// 	TargetDistribution         string  `json:"targetDistribution,omitempty"`
// 	TemporalScore              float64 `json:"temporalScore,omitempty"`
// 	VectorString               string  `json:"vectorString"`
// 	Version                    string  `json:"version"`
// }

// CVSSData was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.0/cvss-v3.0.json
type CVSSData struct {
	Version                       string  `json:"version"`
	VectorString                  string  `json:"vectorString"`
	AttackVector                  string  `json:"attackVector,omitempty"`
	AttackComplexity              string  `json:"attackComplexity,omitempty"`
	Authentication             string  `json:"authentication,omitempty"`
	AccessComplexity           string  `json:"accessComplexity,omitempty"`
	PrivilegesRequired            string  `json:"privilegesRequired,omitempty"`
	UserInteraction               string  `json:"userInteraction,omitempty"`
	Scope                         string  `json:"scope,omitempty"`
	ConfidentialityImpact         string  `json:"confidentialityImpact,omitempty"`
	CollateralDamagePotential  string  `json:"collateralDamagePotential,omitempty"`
	IntegrityImpact               string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact            string  `json:"availabilityImpact,omitempty"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
	AvailabilityRequirement       string  `json:"availabilityRequirement,omitempty"`
	ConfidentialityRequirement    string  `json:"confidentialityRequirement,omitempty"`
	EnvironmentalScore            float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         string  `json:"environmentalSeverity,omitempty"`
	ExploitCodeMaturity           string  `json:"exploitCodeMaturity,omitempty"`
	IntegrityRequirement          string  `json:"integrityRequirement,omitempty"`
	ModifiedAttackComplexity      string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedAttackVector          string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAvailabilityImpact    string  `json:"modifiedAvailabilityImpact,omitempty"`
	ModifiedConfidentialityImpact string  `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       string  `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedPrivilegesRequired    string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedScope                 string  `json:"modifiedScope,omitempty"`
	ModifiedUserInteraction       string  `json:"modifiedUserInteraction,omitempty"`
	RemediationLevel              string  `json:"remediationLevel,omitempty"`
	ReportConfidence              string  `json:"reportConfidence,omitempty"`
	TemporalScore                 float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              string  `json:"temporalSeverity,omitempty"`
	Exploitability             string  `json:"exploitability,omitempty"`
	TargetDistribution         string  `json:"targetDistribution,omitempty"`
}




// CVEAPIJSONDescription was auto-generated.
type CVEAPIJSONDescription struct {
	DescriptionData []*CVEJSON40LangString `json:"description_data"`
}

// NVDCVEAPIFeedJSONDefNode was auto-generated.
// Defines a node or sub-node in an NVD applicability statement.
type NVDCVEAPIFeedJSONDefNode struct {
	CPEMatch []*NVDCVEFeedJSON10DefCPEMatch `json:"cpeMatch,omitempty"`
	// Children []*NVDCVEFeedJSON10DefNode     `json:"children,omitempty"`
	Negate   bool                           `json:"negate,omitempty"`
	Operator string                         `json:"operator,omitempty"`
}

// NVDCVEAPIFeedJSONDefConfigurations was auto-generated.
// Defines the set of product configurations for a NVD applicability statement.
type NVDCVEAPIFeedJSONDefConfigurations struct {
	// CVEDataVersion string                     `json:"CVE_data_version"`
	Nodes          []*NVDCVEAPIFeedJSONDefNode `json:"nodes,omitempty"`
}

// CVEAPIJSONReference was auto-generated.
type CVEAPIJSONReference struct {
	// Name      string   `json:"name,omitempty"`
	Source string   `json:"source,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	URL       string   `json:"url"`
}

// CVEAPIJSONReferences was auto-generated.
type CVEAPIJSONReferences struct {
	ReferenceData []*CVEAPIJSONReference `json:"reference_data"`
}

type CVEAPIJSONWeakness struct {
	Source			string 						`json:"source"`
	Type			string 						`json:"type"`
	Description	 	[]*CVEJSON40LangString 		`json:"description"`
}


// NVDCVEAPIFeedJSONDefImpactBaseMetricV2 was auto-generated.
// CVSS V2.0 score.
type NVDCVEAPIFeedJSONDefImpactBaseMetricV2 struct {
	Source 				string	 `json:"source"`
	Type				string	 `json:"type,omitempty"`
	CVSSData                  *CVSSData `json:"cvssData,omitempty"`
	BaseSeverity                string   `json:"baseSeverity,omitempty"`
	ExploitabilityScore     float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64  `json:"impactScore,omitempty"`
	AcInsufInfo             bool     `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      bool     `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     bool     `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    bool     `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired bool     `json:"userInteractionRequired,omitempty"`
}

// NVDCVEAPIFeedJSONDefImpactBaseMetricV31 was auto-generated.
// CVSS V3.1 score.
type NVDCVEAPIFeedJSONDefImpactBaseMetricV31 struct {
	Source 				string	 `json:"source"`
	Type				string	 `json:"type,omitempty"`
	CVSSData              *CVSSData `json:"cvssData,omitempty"`
	ExploitabilityScore float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64  `json:"impactScore,omitempty"`
}

// NVDCVEAPIFeedJSONDefMetrics was auto-generated.
// Impact scores for a vulnerability as found on NVD.
type NVDCVEAPIFeedJSONDefMetrics struct {
	CVSSMetricV2 []*NVDCVEAPIFeedJSONDefImpactBaseMetricV2 `json:"cvssMetricV2,omitempty"`
	CVSSMetricV30 []*NVDCVEAPIFeedJSONDefImpactBaseMetricV31 `json:"cvssMetricV30,omitempty"`
	CVSSMetricV31 []*NVDCVEAPIFeedJSONDefImpactBaseMetricV31 `json:"cvssMetricV31,omitempty"`
}

func (n *NVDCVEAPIFeedJSONDefMetrics) GetPrimaryV2() *NVDCVEAPIFeedJSONDefImpactBaseMetricV2 {
	if n.CVSSMetricV2 != nil && len(n.CVSSMetricV2) > 0 {
		for _, tmp := range n.CVSSMetricV2 {
			if tmp.Type != "" && tmp.Type == "Primary" {
				return tmp
			}
		}
		return n.CVSSMetricV2[0]
	}
	return nil
} 

func (n *NVDCVEAPIFeedJSONDefMetrics) GetPrimaryV30() *NVDCVEAPIFeedJSONDefImpactBaseMetricV31 {
	if n.CVSSMetricV30 != nil && len(n.CVSSMetricV30) > 0 {
		for _, tmp := range n.CVSSMetricV30 {
			if tmp.Type != "" && tmp.Type == "Primary" {
				return tmp
			}
		}
		return n.CVSSMetricV30[0]
	}
	return nil
} 

func (n *NVDCVEAPIFeedJSONDefMetrics) GetPrimaryV31() *NVDCVEAPIFeedJSONDefImpactBaseMetricV31 {
	if n.CVSSMetricV31 != nil && len(n.CVSSMetricV31) > 0 {
		for _, tmp := range n.CVSSMetricV31 {
			if tmp.Type != "" && tmp.Type == "Primary" {
				return tmp
			}
		}
		return n.CVSSMetricV31[0]
	}
	return nil
} 



// NVDCVEAPIFeedJSONDefCVEItem was auto-generated.
// Defines a vulnerability in the NVD data feed.
type NVDCVEAPIFeedJSONDefCVEItem struct {
	Id				 string								`json:"id"`
	SourceIdentifier string								`json:"sourceIdentifier,omitempty"`
	Published    	 string                             `json:"published,omitempty"`
	LastModified 	 string                             `json:"lastModified,omitempty"`
	VulnStatus 		 string								`json:"vulnStatus,omitempty"`
	Descriptions	 *CVEAPIJSONDescription				`json:"description"`
	Metrics			 *NVDCVEAPIFeedJSONDefMetrics		`json:"metrics,omitempty"`
	Weaknesses		 []*CVEAPIJSONWeakness				`json:"weaknesses,omitempty"`
	Configurations   []*NVDCVEAPIFeedJSONDefConfigurations 		`json:"configurations,omitempty"`
	References		 []*CVEAPIJSONReference			 	`json:"references"`
}

// NVDCVEAPIFeedJSON was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.0/nvd_cve_feed_json_1.0.schema
type NVDCVEAPIFeedJSON struct {
	CVECount 	 uint32                        `json:"cve_count,omitempty"`
	Timestamp    string                        `json:"timestamp,omitempty"`
	CVEItems     []*NVDCVEAPIFeedJSONDefCVEItem `json:"cve_items"`
	Source		 string	`json:"source"`
	FEEDName	 string `json:"feed_name"`
}

type CVEJSON40 struct {
	Affects     *CVEJSON40Affects     `json:"affects"`
	CVEDataMeta *CVEJSON40CVEDataMeta `json:"CVE_data_meta"`
	DataFormat  string                `json:"data_format"`
	DataType    string                `json:"data_type"`
	DataVersion string                `json:"data_version"`
	Description *CVEAPIJSONDescription `json:"description"`
	Problemtype *CVEJSON40Problemtype `json:"problemtype"`
	References  *CVEAPIJSONReferences  `json:"references"`
}