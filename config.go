package vermouth

import (
	"encoding/gob"
	"github.com/ipifony/vermouth/logger"
	"gopkg.in/yaml.v2"
	"os"
	"path/filepath"
	"sync"
)

var GlobalConfig = &Config{}

type Config struct {
	path         string `yaml:"-"`
	sync.RWMutex `yaml:"-"`
	Server       struct {
		ListenPoint       string `yaml:"listen_point"`
		LogInfoPath       string `yaml:"log_info_path"`
		LogErrPath        string `yaml:"log_err_path"`
		CaTrustCache      string `yaml:"ca_trust_cache"`
		DoNotOriginateDir string `yaml:"dno_dir"`
		AdminApiUsername  string `yaml:"admin_api_username"`
		AdminApiPassword  string `yaml:"admin_api_password"`
		InstanceId        string `yaml:"instance_id"`
		TelemetryDisabled bool   `yaml:"telemetry_disabled"`
	} `yaml:"server"`
	StiPa struct {
		RootPath    string   `yaml:"root_path"`
		CrlUrls     []string `yaml:"crl_urls"`
		ApiBaseUrl  string   `yaml:"api_base_url"`
		ApiUserId   string   `yaml:"api_user_id"`
		ApiPassword string   `yaml:"api_password"`
	} `yaml:"sti_pa"`
	StiAs struct {
		CarrierOcn            string `yaml:"carrier_ocn"`
		AcmeProdEnabled       bool   `yaml:"acme_prod_enabled"`
		AcmeAcctKeyFile       string `yaml:"acme_acct_key_file"`
		AcmeAcctKeyBound      bool   `yaml:"acme_acct_key_bound"`
		AcmeAcctLocationUrl   string `yaml:"acme_acct_location_url"`
		AcmeEabKeyId          string `yaml:"acme_eab_key_id"`
		AcmeEabKeySecret      string `yaml:"acme_eab_key_secret"`
		AcmeStiPaSpcToken     string `yaml:"acme_sti_pa_spc_token"`
		AcmeStiPaCrlUri       string `yaml:"acme_sti_pa_crl_uri"`
		AcmeStiPaCrlIssuer    string `yaml:"acme_sti_pa_crl_issuer"`
		AcmeCrlUriFallback    string `yaml:"acme_crl_uri_fallback"`
		AcmeCrlIssuerFallback string `yaml:"acme_crl_issuer_fallback"`
		AcmeDir               string `yaml:"acme_dir"`
	} `yaml:"sti_as"`
	StiVs struct {
		StrictCrlHandling bool `yaml:"strict_crl_handling"`
	} `yaml:"sti_vs"`
	Database struct {
		Enabled  bool   `yaml:"enabled"`
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
		DbName   string `yaml:"db_name"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"database"`
}

func (ourConfig *Config) isDbEnabled() bool {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.Database.Enabled
}

func (ourConfig *Config) PrepareDbUrl() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return "postgres://" + ourConfig.Database.Username + ":" + ourConfig.Database.Password + "@" +
		ourConfig.Database.Host + ":" + ourConfig.Database.Port + "/" + ourConfig.Database.DbName
}

func (ourConfig *Config) IsTelemetryDisabled() bool {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.Server.TelemetryDisabled
}
func (ourConfig *Config) GetServerLogInfoPath() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.Server.LogInfoPath
}
func (ourConfig *Config) GetServerLogErrPath() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.Server.LogErrPath
}
func (ourConfig *Config) GetServerCaTrustCache() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.Server.CaTrustCache
}
func (ourConfig *Config) GetDNODir() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.Server.DoNotOriginateDir
}
func (ourConfig *Config) GetServerAdminApiUsername() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.Server.AdminApiUsername
}
func (ourConfig *Config) GetServerAdminApiPassword() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.Server.AdminApiPassword
}
func (ourConfig *Config) GetServerInstanceId() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.Server.InstanceId
}
func (ourConfig *Config) GetStiPaRootPath() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiPa.RootPath
}
func (ourConfig *Config) GetStiPaApiCrlUrls() []string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiPa.CrlUrls
}
func (ourConfig *Config) GetStiPaApiBaseUrl() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiPa.ApiBaseUrl
}
func (ourConfig *Config) GetStiPaApiUserId() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiPa.ApiUserId
}
func (ourConfig *Config) GetStiPaApiPassword() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiPa.ApiPassword
}
func (ourConfig *Config) GetStiAsAcmeAcctId() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeEabKeyId
}
func (ourConfig *Config) GetStiAsAcmeEabKeyId() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeEabKeyId
}
func (ourConfig *Config) GetStiAsAcmeEabKeySecret() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeEabKeySecret
}
func (ourConfig *Config) GetStiAsCarrierOcn() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.CarrierOcn
}
func (ourConfig *Config) isAcmeProdMode() bool {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeProdEnabled
}
func (ourConfig *Config) GetStiAsAcmeAcctKeyFile() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeAcctKeyFile
}
func (ourConfig *Config) GetStiAsAcmeDir() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeDir
}
func (ourConfig *Config) getStiAsAcmeAcctLocationUrl() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeAcctLocationUrl
}
func (ourConfig *Config) IsStiAsAcmeAcctKeyBound() bool {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeAcctKeyBound
}
func (ourConfig *Config) getStiAsAcmeStiPaSpcToken() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeStiPaSpcToken
}
func (ourConfig *Config) getStiAsAcmeStiPaCrlUri() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeStiPaCrlUri
}
func (ourConfig *Config) getStiAsAcmeStiPaCrlIssuer() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeStiPaCrlIssuer
}
func (ourConfig *Config) getStiAsAcmeCrlUriFallback() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeCrlUriFallback
}
func (ourConfig *Config) getStiAsAcmeCrlIssuerFallback() string {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiAs.AcmeCrlIssuerFallback
}

func (ourConfig *Config) getListenPoint() string {
	if len(ourConfig.Server.ListenPoint) == 0 {
		return "127.0.0.1:8085"
	}
	return ourConfig.Server.ListenPoint
}

func (ourConfig *Config) isStrictCrlHandling() bool {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	return ourConfig.StiVs.StrictCrlHandling
}

func (ourConfig *Config) setStiAsAcmeAcctKeyBound(binding bool) {
	ourConfig.Lock()
	defer ourConfig.Unlock()
	ourConfig.StiAs.AcmeAcctKeyBound = binding
}
func (ourConfig *Config) setStiAsAcmeAcctLocationUrl(url string) {
	ourConfig.Lock()
	defer ourConfig.Unlock()
	ourConfig.StiAs.AcmeAcctLocationUrl = url
}
func (ourConfig *Config) setStiAsAcmeStiPaSpcToken(token string) {
	ourConfig.Lock()
	defer ourConfig.Unlock()
	ourConfig.StiAs.AcmeStiPaSpcToken = token
}
func (ourConfig *Config) setStiAsAcmeStiPaCrlUri(crl string) {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	ourConfig.StiAs.AcmeStiPaCrlUri = crl
}
func (ourConfig *Config) setStiAsAcmeStiPaCrlIssuer(iss string) {
	ourConfig.RLock()
	defer ourConfig.RUnlock()
	ourConfig.StiAs.AcmeStiPaCrlIssuer = iss
}
func (ourConfig *Config) SetServerInstanceId(instanceId string) {
	ourConfig.Lock()
	defer ourConfig.Unlock()
	ourConfig.Server.InstanceId = instanceId
}

func (ourConfig *Config) setDbEnabled(enabled bool) {
	ourConfig.Lock()
	defer ourConfig.Unlock()
	ourConfig.Database.Enabled = enabled
}

func (ourConfig *Config) Save() {
	data, err := yaml.Marshal(ourConfig)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Could not persist config"}
		return
	}
	ourConfig.Lock()
	defer ourConfig.Unlock()
	_ = os.WriteFile(ourConfig.path, data, 0777)
}

func (ourConfig *Config) LoadConfig(path string) error {
	ourConfig.path = path
	return ourConfig.ReloadConfig()
}

func (ourConfig *Config) ReloadConfig() error {
	tmpCfg := &Config{}

	file, err := os.Open(ourConfig.path)
	if err != nil {
		return err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	if err := d.Decode(&tmpCfg); err != nil {
		return err
	}
	ourConfig.Lock()
	defer ourConfig.Unlock()
	_ = os.MkdirAll(tmpCfg.StiAs.AcmeDir, 0755)
	_ = os.MkdirAll(filepath.Dir(tmpCfg.Server.CaTrustCache), 0755)
	_ = os.MkdirAll(filepath.Dir(tmpCfg.Server.LogInfoPath), 0755)
	_ = os.MkdirAll(filepath.Dir(tmpCfg.Server.LogErrPath), 0755)

	ourConfig.Server = tmpCfg.Server
	ourConfig.StiPa = tmpCfg.StiPa
	ourConfig.StiAs = tmpCfg.StiAs
	ourConfig.Database = tmpCfg.Database

	return nil
}

func writeGob(filePath string, object interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	encoder := gob.NewEncoder(file)
	_ = encoder.Encode(object)
	_ = file.Close()
	return err
}

func readGob(filePath string, object interface{}) error {
	file, err := os.Open(filePath)
	if err == nil {
		decoder := gob.NewDecoder(file)
		err = decoder.Decode(object)
	}
	_ = file.Close()
	return err
}
