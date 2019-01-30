package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	ar "github.com/m-mizutani/AlertResponder/lib"
	"github.com/pkg/errors"
)

type SecretValues struct {
	VirusTotalToken string `json:"virustotal_token"`
}

type malwareCache map[string]*VirusTotalFileReport

func createMalwareCache(hashList []string, vt *VirusTotal) (malwareCache, error) {
	vd := make(malwareCache)

	reports, err := vt.QueryFileBulk(hashList)
	if err != nil {
		return nil, err
	}

	for i := range reports {
		vd[reports[i].SHA256] = &reports[i]
	}

	return vd, nil
}

func traceMalware(report VirusTotalIPAddrReport, vt *VirusTotal) ([]ar.ReportMalware, error) {
	mwTemp := []ar.ReportMalware{}
	mwReport := []ar.ReportMalware{}
	hashList := []string{}

	targetVendors := []string{
		"Kaspersky",
		"TrendMicro",
		"Sophos",
		"Microsoft",
		"Symantec",
	}

	convMalwareReport := func(targets []VtSample, relation string) {
		for _, sample := range targets {
			t, err := time.Parse("2006-01-02 15:04:05", sample.Date)
			if err != nil {
				log.Println("Error: Invalid time format of VT result, ", sample.Date)
				continue
			}

			mwTemp = append(mwTemp, ar.ReportMalware{
				SHA256:    sample.SHA256,
				Timestamp: t,
				Relation:  relation,
			})
		}
	}
	convMalwareReport(report.DetectedCommunicatingSamples, "communicated")
	convMalwareReport(report.DetectedDownloadedSamples, "downloaded")
	convMalwareReport(report.DetectedReferrerSamples, "emmbeded")

	const maxItemCount int = 8

	sort.Slice(mwTemp, func(i, j int) bool { // Reverse sort
		return mwTemp[i].Timestamp.After(mwTemp[j].Timestamp)
	})

	for i := 0; i < maxItemCount && i < len(mwTemp); i++ {
		mwReport = append(mwReport, mwTemp[i])
		hashList = append(hashList, mwTemp[i].SHA256)
	}

	cache, err := createMalwareCache(hashList, vt)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(mwReport); i++ {
		r := &mwReport[i]
		scanResult, ok := cache[r.SHA256]
		if !ok {
			log.Println("No scan result:", r.SHA256)
			continue
		}

		for _, vendor := range targetVendors {
			scan, ok := scanResult.Scans[vendor]
			scanReport := ar.ReportMalwareScan{Vendor: vendor, Source: "VirusTotal"}

			if ok && scan.Detected {
				scanReport.Positive = true
				scanReport.Name = scan.Result
			}

			r.Scans = append(r.Scans, scanReport)
		}
	}

	return mwReport, nil
}

func traceDomain(resolutions []vtResolution) []ar.ReportDomain {
	const maxItemCount = 5
	tmp := []ar.ReportDomain{}
	domainReports := []ar.ReportDomain{}

	for _, resolution := range resolutions {
		t, err := time.Parse("2006-01-02 15:04:05", resolution.LastResolved)
		if err != nil {
			log.Println("Error: Invalid time format of VT result, ", resolution)
			continue
		}

		tmp = append(tmp, ar.ReportDomain{
			Name:      resolution.HostName,
			Timestamp: t,
			Source:    "VirusTotal",
		})
	}

	sort.Slice(tmp, func(i, j int) bool { // Reverse sort
		return tmp[i].Timestamp.After(tmp[j].Timestamp)
	})

	for i := 0; i < maxItemCount && i < len(tmp); i++ {
		domainReports = append(domainReports, tmp[i])
	}

	return domainReports
}

func traceURL(urls []vtURL) []ar.ReportURL {
	const maxItemCount = 5
	tmp := []ar.ReportURL{}
	urlReports := []ar.ReportURL{}

	for _, url := range urls {
		if url.Positives == 0 {
			continue
		}

		t, err := time.Parse("2006-01-02 15:04:05", url.ScanDate)
		if err != nil {
			log.Println("Error: Invalid time format of VT result, ", url)
			continue
		}

		tmp = append(tmp, ar.ReportURL{
			URL:       url.URL,
			Timestamp: t,
			Source:    "VirusTotal",
		})
	}

	sort.Slice(tmp, func(i, j int) bool { // Reverse sort
		return tmp[i].Timestamp.After(tmp[j].Timestamp)
	})

	for i := 0; i < maxItemCount && i < len(tmp); i++ {
		urlReports = append(urlReports, tmp[i])
	}

	return urlReports
}

func SpyRemoteIPAddr(ipaddr, token string) (*ar.ReportPage, error) {
	vt := NewVirusTotal(token)

	report, err := vt.QueryIPAddr(ipaddr)
	if err != nil {
		return nil, err
	}

	mwReports, err := traceMalware(report, &vt)
	if err != nil {
		return nil, err
	}

	remote := ar.ReportOpponentHost{
		IPAddr:         []string{ipaddr},
		RelatedMalware: mwReports,
		RelatedDomains: traceDomain(report.Resolutions),
		RelatedURLs:    traceURL(report.DetectedURLs),
	}

	page := ar.NewReportPage()
	page.Title = fmt.Sprintf("VirusTotal Report of %s", ipaddr)
	page.OpponentHosts = append(page.OpponentHosts, remote)

	return &page, nil
}

func sliceHasWord(arr []string, target string) bool {
	for _, s := range arr {
		if s == target {
			return true
		}
	}

	return false
}

func SpyRemoteHost(task ar.Task) (*ar.ReportPage, error) {
	// ar.Dump("task", task)

	var values SecretValues
	err := ar.GetSecretValues(os.Getenv("SECRET_ARN"), &values)
	if err != nil {
		return nil, errors.Wrap(err, "Fail to get VT secrets")
	}

	if sliceHasWord(task.Attr.Context, "remote") && task.Attr.Type == "ipaddr" {
		return SpyRemoteIPAddr(task.Attr.Value, values.VirusTotalToken)
	}

	return nil, nil
}

func main() {
	funcName := os.Getenv("SUBMITTER_NAME")
	funcRegion := os.Getenv("SUBMITTER_REGION")
	ar.Inspect(SpyRemoteHost, funcName, funcRegion)
}
