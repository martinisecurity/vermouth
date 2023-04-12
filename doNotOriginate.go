package vermouth

import (
	"archive/zip"
	"bufio"
	"errors"
	"fmt"
	"github.com/ipifony/vermouth/logger"
	"github.com/xuri/excelize/v2"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DNOLastFetchFile   = `dno_last_fetch`
	NANPACoURL         = `https://www.nationalnanpa.com/nanp1/allutlzd.zip`
	NANPACoZip         = `vermouth.nanpa-us.zip`
	NANPAAreaCodesUrl  = `https://www.nationalnanpa.com/enas/downloadGeoAreaCodeAlphabetReport.do`
	NANPAAreaCodesXlsx = `vermouth.npa-all.xlsx`
)

const DNOResponseHeader = "X-Vermouth-Robostatus"

const (
	DNOStatusGood    = "good"
	DNOStatusBogon   = "bogon"
	DNOStatusBlocked = "blocked"
)

const (
	DNOCategoryUS = iota
	DNOCategoryOther
)

var doNotOriginate = &DNO{}

func prepArtifacts() error {
	var lastFetchTime time.Time
	lastFetchPath := path.Join(GlobalConfig.GetDNODir(), DNOLastFetchFile)
	readBytes, readErr := os.ReadFile(lastFetchPath)
	if readErr == nil {
		lastFetchTime.GobDecode(readBytes)
	}

	usNanpaCoPath := filepath.Join(GlobalConfig.GetDNODir(), NANPACoZip)
	npaPath := filepath.Join(GlobalConfig.GetDNODir(), NANPAAreaCodesXlsx)

	// If we have valid artifacts that are less than 7 days old, we are already done here
	if readErr == nil && lastFetchTime.Add(7*24*time.Hour).After(time.Now()) {
		npaMapFileInfo, npaMapPathErr := os.Stat(npaPath)
		usNanpaFileInfo, usNanpapathErr := os.Stat(usNanpaCoPath)
		if usNanpapathErr == nil && usNanpaFileInfo.Size() > 0 && npaMapPathErr == nil && npaMapFileInfo.Size() > 0 {
			logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "DNO: Existing Artifacts seem valid...Last fetched: " + lastFetchTime.String()}
			return nil
		}
	}

	err := downloadFile(usNanpaCoPath, true, NANPACoURL)
	if err != nil {
		return err
	}
	err = downloadFile(npaPath, false, NANPAAreaCodesUrl)
	if err != nil {
		return err
	}

	lastFetchTime = time.Now()

	// If we couldn't persist this, but the artifacts saved then the timer will hit normally if the process stays up.
	timeBytes, err := lastFetchTime.GobEncode()
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "DNO: Unable to encode time gob. " + err.Error()}
		return nil
	}
	f, err := os.Create(lastFetchPath)
	defer f.Close()
	f.Write(timeBytes)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "DNO: Unable to persist recent fetch time data. " + err.Error()}
	}

	return nil
}

func refreshDNO(responseChan chan<- Message) {
	statusMsg := Message{
		MessageSender: DNOWorker,
		MessageType:   Failure,
		MsgStr:        "",
	}

	// We need to make sure a few files are ready. Download them or just use what is there
	artifactsErr := prepArtifacts()
	if artifactsErr != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "DNO: Error populating NPA Map"}
		responseChan <- statusMsg
		return
	}

	npaMap, err := populateNPA()
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "DNO: Error populating NPA Map"}
		responseChan <- statusMsg
		return
	}
	err = handleUsExchanges(npaMap)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "DNO: Error adding US exchange bogons"}
		responseChan <- statusMsg
		return
	}
	// Iterate over keys (NPAs)
	for k := range npaMap {
		// Ignore non-geographical / non-US area codes
		if npaMap[k].Category != DNOCategoryUS {
			npaMap[k] = &BogonExchanges{Category: DNOCategoryOther}
			continue
		}

		// Prepare to invert matches for smaller search space
		var bogons []string
		for i := 200; i < 1000; i++ {
			found := false
			testCo := strconv.Itoa(i)
			for _, goodCo := range npaMap[k].CoCodes {
				if testCo == goodCo {
					found = true
					break
				}
			}
			if !found {
				bogons = append(bogons, testCo)
			}
		}
		npaMap[k].CoCodes = bogons
	}

	doNotOriginate.Lock()
	doNotOriginate.NpaMap = npaMap
	doNotOriginate.Unlock()

	statusMsg.MessageType = Success
	responseChan <- statusMsg
}

func populateNPA() (map[string]*BogonExchanges, error) {
	npaMap := make(map[string]*BogonExchanges)

	path := filepath.Join(GlobalConfig.GetDNODir(), NANPAAreaCodesXlsx)

	f, err := excelize.OpenFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rows, err := f.GetRows("NpasInServiceByLocation")
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, errors.New("no rows found")
	}
	for rowIndex, row := range rows {
		if rowIndex == 0 {
			continue
		}
		if len(row[0]) < 1 || len(row[1]) < 1 {
			return nil, errors.New("unable to read row values")
		}
	}
	return npaMap, nil
}

func handleUsExchanges(npaMap map[string]*BogonExchanges) error {
	path := filepath.Join(GlobalConfig.GetDNODir(), NANPACoZip)

	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer archive.Close()

	file, err := archive.Open("allutlzd.txt")
	if err != nil {
		return err
	}

	readCloser := io.ReadCloser(file)
	defer readCloser.Close()

	scanner := bufio.NewScanner(readCloser)
	// Advance past the header
	scanner.Scan()

	for scanner.Scan() {
		slice := strings.Split(scanner.Text(), "\t")
		if slice[6] != "AS" {
			// Only Assigned
			continue
		}
		npanxx := strings.Split(slice[1], "-")
		if len(npanxx[0]) != 3 || len(npanxx[1]) != 3 {
			continue
		}
		if npaMap[npanxx[0]] == nil {
			npaMap[npanxx[0]] = &BogonExchanges{Category: DNOCategoryUS}
		}
		npaMap[npanxx[0]].CoCodes = append(npaMap[npanxx[0]].CoCodes, npanxx[1])
	}
	return nil
}

func (dno *DNO) getDNOStatusForCaller(tn string) string {
	// DNO hasn't been refreshed yet or there was an error at some point.
	if len(dno.NpaMap) == 0 {
		return DNOStatusGood
	}

	// Let's add a few checks to rule out non NANPA CIDs (+1)NXX-NXX-XXXX where N is 2-9 and X is 0-9
	// Ultimately, we regard non-US numbers are automatically good
	if len(tn) < 10 || len(tn) > 12 {
		return DNOStatusGood
	}
	if len(tn) == 12 && strings.HasPrefix(tn, "+1") {
		tn = tn[2:]
	} else {
		return DNOStatusGood
	}
	if len(tn) == 11 && strings.HasPrefix(tn, "1") {
		tn = tn[1:]
	} else {
		return DNOStatusGood
	}
	// We need to make sure the area code and CO code (exchange) do not start 0 or 1 -- ASCII Decimal values 48,49
	areaCode := tn[0:3]
	if areaCode[0] == 48 || areaCode[0] == 49 {
		return DNOStatusBogon
	}
	exchange := tn[3:6]
	if exchange[0] == 48 || exchange[0] == 49 {
		return DNOStatusBogon
	}

	dno.RLock()
	defer dno.RUnlock()

	exchanges := dno.NpaMap[areaCode]
	if exchanges == nil {
		return DNOStatusBogon
	}
	if exchanges.Category == DNOCategoryOther {
		return DNOStatusGood
	}
	if stringInSlice(exchange, exchanges.CoCodes) {
		return DNOStatusBogon
	}
	return DNOStatusGood
}

func dumpDNO() {
	totalBlacklisted := 0
	for k, v := range doNotOriginate.NpaMap {
		totalBlacklisted += len(v.CoCodes)
		fmt.Printf("key[%s] value[%s]\n", k, strings.Join(v.CoCodes, ", "))
	}
	fmt.Println("blacklisted", totalBlacklisted)
}

func downloadFile(filepath string, useGet bool, url string) error {
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "DNO: Fetching resource from " + url}
	var resp *http.Response
	var err error
	if useGet {
		resp, err = http.Get(url)
	} else {
		resp, err = http.Post(url, "", nil)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

type DNO struct {
	sync.RWMutex
	NpaMap map[string]*BogonExchanges
}
type BogonExchanges struct {
	Category int
	CoCodes  []string
}
