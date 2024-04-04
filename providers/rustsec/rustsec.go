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

// Package rustsec provides a converter for rustsec advisories to nvd.
package rustsec

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	nvd "github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

// Convert scans a directory recursively for rustsec advisory files and convert to NVD CVE JSON 1.0 format.
func Convert(dir string) (*nvd.NVDCVEAPIFeedJSON, error) {
	feed := &nvd.NVDCVEAPIFeedJSON{}

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		_, fn := filepath.Split(path)
		if !(strings.HasPrefix(fn, "RUSTSEC") && strings.HasSuffix(fn, ".md")) {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		cve, err := ConvertAdvisory(f)
		if err != nil {
			return errors.Wrapf(err, "error parsing file: %s", path)
		}
		feed.CVEItems = append(feed.CVEItems, cve)
		return nil
	}

	err := filepath.Walk(dir, walker)
	if err != nil {
		return nil, err
	}

	return feed, nil
}

// ConvertAdvisory converts the rustsec toml advisory data from r to NVD CVE JSON 1.0 format.
func ConvertAdvisory(r io.Reader) (*nvd.NVDCVEAPIFeedJSONDefCVEItem, error) {
	var spec advisoryFile

	bs, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "cannot read RUSTSEC file")
	}

	reg := regexp.MustCompile("(?s)" + // global flag - . also matches newline
		"```toml\\n(.+?)```" + // 1 group - match toml part (between ```toml and ```) in lazy mode
		"(?s:[\\s\\n]*)" + // match any number of new lines and spaces before first #
		"#\\s*(\\S.*?)\\n" + // get title - from # to new line in lazy mode
		"(?s:[\\s\\n]*)" + // skip the newlines and spaces
		"(.*)") // everything else is description

	data := reg.FindStringSubmatch(string(bs))
	if (data == nil) || (len(data) != 4) {
		return nil, errors.New("cannot parse md advisory structure")
	}
	_, err = toml.Decode(data[1], &spec)

	if err != nil {
		return nil, errors.Wrap(err, "cannot decode rustsec toml advisory part of md file")
	}

	spec.Item.Title = data[2]
	spec.Item.Description = data[3]

	return spec.Item.Convert()
}

// advisoryFile is the toml spec for rustsec advisories.
// Ref: https://github.com/RustSec/advisory-db
type advisoryFile struct {
	Item advisoryItem `toml:"advisory"`
}

type advisoryItem struct {
	ID                 string   `toml:"id"`
	Package            string   `toml:"package"`
	Date               string   `toml:"date"`
	Title              string   `toml:"title"`
	Description        string   `toml:"description"`
	URL                string   `toml:"url"`
	Aliases            []string `toml:"aliases"`
	Keywords           []string `toml:"keywords"`
	References         []string `toml:"references"`
	PatchedVersions    []string `toml:"patched_versions"`
	AffectedArch       []string `toml:"affected_arch"`
	AffectedOS         []string `toml:"affected_os"`
	AffectedFunctions  []string `toml:"affected_functions"`
	UnaffectedVersions []string `toml:"unaffected_versions"`
}

const advisoryTimeLayout = "2006-01-02"

func (item *advisoryItem) Convert() (*nvd.NVDCVEAPIFeedJSONDefCVEItem, error) {
	// TODO: Add CVSS score: https://github.com/RustSec/advisory-db/issues/20

	t, err := time.Parse(advisoryTimeLayout, item.Date)
	if err != nil {
		return nil, errors.Wrapf(err, "malformed date layout in %#v: %q", item, item.Date)
	}

	conf, err := item.newConfigurations()
	if err != nil {
		return nil, err
	}

	cve := &nvd.NVDCVEAPIFeedJSONDefCVEItem{
		Id: item.ID,
		SourceIdentifier: "RustSec",
		Descriptions: &nvd.CVEAPIJSONDescription{
			DescriptionData: []*nvd.CVEJSON40LangString{
				{
					Lang:  "en",
					Value: item.Description,
				},
			},
		},
		References: item.newReferences(),
		Configurations:   conf,
		LastModified: t.Format(nvd.TimeLayout),
		Published:    t.Format(nvd.TimeLayout),
	}

	return cve, nil
}

func (item *advisoryItem) newReferences() []*nvd.CVEAPIJSONReference {
	if len(item.References) == 0 {
		return nil
	}

	nrefs := 1 + len(item.Aliases) + len(item.References)
	refs := &nvd.CVEAPIJSONReferences{
		ReferenceData: make([]*nvd.CVEAPIJSONReference, 0, nrefs),
	}

	addRef := func(_, url string) {
		refs.ReferenceData = append(refs.ReferenceData, &nvd.CVEAPIJSONReference{
			URL:  url,
		})
	}

	if item.Title != "" || item.URL != "" {
		addRef(item.Title, item.URL)
	}

	for _, ref := range item.Aliases {
		addRef(ref, "")
	}

	for _, ref := range item.References {
		addRef(ref, "")
	}

	rd := refs.ReferenceData
	sort.Slice(rd, func(i, j int) bool {
		return strings.Compare(rd[i].URL, rd[j].URL) < 0
	})

	return refs.ReferenceData
}

func (item *advisoryItem) newConfigurations() (*nvd.NVDCVEAPIFeedJSONDefConfigurations, error) {
	pkg, err := wfn.WFNize(item.Package)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot wfn-ize: %q", item.Package)
	}
	cpe := wfn.Attributes{Part: "a", Product: pkg}
	// cpe22uri := cpe.BindToURI()
	cpe23uri := cpe.BindToFmtString()

	matches := []*nvd.NVDCVEFeedJSON10DefCPEMatch{}
	unnafected := append(item.UnaffectedVersions, item.PatchedVersions...)

	for _, version := range unnafected {
		if len(version) < 2 {
			return nil, errors.Errorf("malformed version schema in %#v: %q", item, version)
		}

		var curver string

		switch version[:1] {
		case "=", "^":
			curver = strings.TrimSpace(version[1:])
			wfnver, err := wfn.WFNize(curver)
			if err != nil {
				return nil, errors.Wrapf(err, "cannot wfn-ize version: %q", curver)
			}
			cpe := wfn.Attributes{Part: "a", Product: pkg, Version: wfnver}
			// cpe22uri := cpe.BindToURI()
			cpe23uri := cpe.BindToFmtString()
			match := &nvd.NVDCVEFeedJSON10DefCPEMatch{
				Criteria:   cpe23uri,
				Vulnerable: version[:1] == "=",
			}
			matches = append(matches, match)

		case ">", "<":
			match := &nvd.NVDCVEFeedJSON10DefCPEMatch{
				Criteria:   cpe23uri,
				Vulnerable: false, // these are patched + unaffected versions
			}
			curver = strings.TrimSpace(version[2:])
			switch version[:2] {
			case "> ":
				match.VersionStartExcluding = curver
			case ">=":
				match.VersionStartIncluding = curver
			case "< ":
				match.VersionEndExcluding = curver
			case "<=":
				match.VersionEndIncluding = curver
			default:
				return nil, errors.Errorf("malformed version schema in %#v: %q", item, version)
			}
			matches = append(matches, match)

		default:
			return nil, errors.Errorf("malformed version schema in %#v: %q", item, version)
		}
	}

	conf := &nvd.NVDCVEAPIFeedJSONDefConfigurations{
		Nodes: []*nvd.NVDCVEAPIFeedJSONDefNode{
			{
				Operator: "AND",
				// Children: []*nvd.NVDCVEAPIFeedJSONDefNode{
				// 	{
				// 		CPEMatch: []*nvd.NVDCVEFeedJSON10DefCPEMatch{
				// 			{
				// 				CPEName: []*nvd.NVDCVEFeedJSON10DefCPEName{
				// 					{
				// 						Cpe22Uri: cpe22uri,
				// 						Cpe23Uri: cpe23uri,
				// 					},
				// 				},
				// 				Criteria:              cpe23uri,
				// 				Vulnerable:            false,
				// 				VersionStartIncluding: "0",
				// 			},
				// 		},
				// 	},
				// 	{
				// 		Negate:   true,
				// 		CPEMatch: matches,
				// 	},
				// },
			},
		},
	}

	return conf, nil
}
