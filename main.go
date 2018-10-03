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

func traceMalware(report VirusTotalIPAddrReport, vt *VirusTotal) ([]ar.ReportMalware, []ar.Section, error) {
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
		return nil, nil, err
	}

	table := ar.NewTable()
	table.Head.AddItem("Datetime")
	table.Head.AddItem("Ratio")
	table.Head.AddItem("Type")

	for _, vendor := range targetVendors {
		table.Head.AddItem(vendor)
	}

	for _, r := range mwReport {
		scanResult, ok := cache[r.SHA256]
		if !ok {
			log.Println("No scan result:", r.SHA256)
			continue
		}

		row := ar.NewRow()
		row.AddItem(fmt.Sprintf("[%s](https://www.virustotal.com/ja/file/%s/analysis/)", r.Timestamp, r.SHA256))
		row.AddItem(fmt.Sprintf("%d/%d", scanResult.Positives, scanResult.Total))
		row.AddItem(r.Relation)

		for _, vendor := range targetVendors {
			scan, ok := scanResult.Scans[vendor]
			scanReport := ar.ReportMalwareScan{Vendor: vendor}

			if !ok || !scan.Detected {
				row.AddItem("")
			} else {
				row.AddItem(scan.Result)
				scanReport.Positive = true
				scanReport.Name = scan.Result
			}

			r.Scans = append(r.Scans, ar.ReportMalwareScan{})
		}

		table.Append(row)
	}

	section := ar.NewSection("Related malware")
	section.Append(&table)

	return mwReport, []ar.Section{section}, nil
}

func SpyRemoteIPAddr(ipaddr, token string) (*ar.ReportPage, error) {
	vt := NewVirusTotal(token)

	report, err := vt.QueryIPAddr(ipaddr)
	if err != nil {
		return nil, err
	}

	mwReports, mwSections, err := traceMalware(report, &vt)
	if err != nil {
		return nil, err
	}

	page := ar.NewReportPage()
	page.Title = fmt.Sprintf("VirusTotal Report of %s", ipaddr)
	page.AppendSections(mwSections)
	page.RemoteHost = &ar.ReportRemoteHost{
		IPAddr:         []string{ipaddr},
		RelatedMalware: mwReports,
	}

	return &page, nil
}

func SpyRemoteHost(task ar.Task) (*ar.ReportPage, error) {
	ar.Dump("task", task)

	var values SecretValues
	err := ar.GetSecretValues(os.Getenv("SECRET_ARN"), &values)
	if err != nil {
		return nil, errors.Wrap(err, "Fail to get VT secrets")
	}

	if task.Attr.Context == "remote" && task.Attr.Type == "ipaddr" {
		return SpyRemoteIPAddr(task.Attr.Value, values.VirusTotalToken)
	}

	return nil, nil
}

func main() {
	tableName := os.Getenv("REPORT_DATA")
	ar.Inspect(SpyRemoteHost, tableName)
}
