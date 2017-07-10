/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package config

import (
	"bytes"
	"fmt"
	"github.com/spf13/viper"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

// init loads the default config file
func init() {
	viper.AddConfigPath("$GOPATH/src/github.com/xlab-si/emmy/config")
	loadConfig("defaults", "yml")
}

// setDefaults sets default values for all emmy configuration.
func setDefaults() {
	viper.SetDefault("ip", "localhost")
	viper.SetDefault("port", 7007)
	viper.SetDefault("timeout", 5)
	viper.SetDefault("key_folder", "/tmp")

	p := "16714772973240639959372252262788596420406994288943442724185217359247384753656472309049760952976644136858333233015922583099687128195321947212684779063190875332970679291085543110146729439665070418750765330192961290161474133279960593149307037455272278582955789954847238104228800942225108143276152223829168166008095539967222363070565697796008563529948374781419181195126018918350805639881625937503224895840081959848677868603567824611344898153185576740445411565094067875133968946677861528581074542082733743513314354002186235230287355796577107626422168586230066573268163712626444511811717579062108697723640288393001520781671"
	g := "13435884250597730820988673213378477726569723275417649800394889054421903151074346851880546685189913185057745735207225301201852559405644051816872014272331570072588339952516472247887067226166870605704408444976351128304008060633104261817510492686675023829741899954314711345836179919335915048014505501663400445038922206852759960184725596503593479528001139942112019453197903890937374833630960726290426188275709258277826157649744326468681842975049888851018287222105796254410594654201885455104992968766625052811929321868035475972753772676518635683328238658266898993508045858598874318887564488464648635977972724303652243855656"
	q := "98208916160055856584884864196345443685461747768186057136819930381973920107591"

	pgq := map[string]string{
		"p": p,
		"g": g,
		"q": q,
	}
	viper.SetDefault("pedersen", pgq)
	viper.SetDefault("schnorr", pgq)

	pseudonymSysConfig := map[string]interface{}{
		"p":     p,
		"g":     g,
		"q":     q,
		"user1": "10501840420714326611674814933629820564884994433464121609699657686381725481917946560951300989428757857663890749444810669658158959171443678666294156633031855300155147813954782039163197859065107569638424682758546743970421679581497316473363590677852615245790857416631205041294470157319811083478928657427332727532272060990285330797695681228920548209293494826378319240408357619741465896984159808329187249915415180748872721286083954030337580803742552856969769146625693488160927221403705265205532491725454404938155197720048433342625635727130205282673205600167729513490481034307616261949529737060447713783467988717455504863857",
		"org1":  "",
		"org2":  "",
		"ca":    "",
	}
	viper.SetDefault("pseudonymsys", pseudonymSysConfig)
}

// LoadCustomConfigFromFile loads custom configuration from file "dirPath/configName.configType".
func LoadCustomConfigFromFile(dirPath, configName, configType string) error {
	viper.AddConfigPath(dirPath)
	return loadConfig(configName, configType)
}

// LoadCustomConfigFromBugger loads custom configuration from a buffer.
func LoadCustomConfigFromBuffer(config []byte) error {
	if err := viper.ReadConfig(bytes.NewBuffer(config)); err != nil {
		return fmt.Errorf("Cannot read configuration file: %s\n", err)
	}

	return nil
}

// LoadConfig reads in the config file with configName being the name of the file (without suffix)
// and configType being "yml" or "json".
func loadConfig(configName, configType string) error {
	viper.SetConfigName(configName)
	viper.SetConfigType(configType)

	err := viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("Cannot read configuration file: %s\n", err)
	}

	return nil
}

// LoadServerPort returns the port where emmy server will be listening.
func LoadServerPort() int {
	return viper.GetInt("port")
}

// LoadServerEndpoint returns the endpoint of the emmy server where clients will be contacting it.
func LoadServerEndpoint() string {
	ip := viper.GetString("ip")
	port := LoadServerPort()
	return fmt.Sprintf("%v:%v", ip, port)
}

// LoadTimeout returns the specified number of seconds that clients wait before giving up
// on connection to emmy server
func LoadTimeout() float64 {
	return viper.GetFloat64("timeout")
}

func LoadKeyDirFromConfig() string {
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadTestdataDir() string {
	return viper.GetString("testdata_dir")
}

func LoadTestKeyDirFromConfig() string {
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadGroup(scheme string) *groups.SchnorrGroup {
	groupMap := viper.GetStringMap(scheme)
	p, _ := new(big.Int).SetString(groupMap["p"].(string), 10)
	g, _ := new(big.Int).SetString(groupMap["g"].(string), 10)
	q, _ := new(big.Int).SetString(groupMap["q"].(string), 10)
	return groups.NewSchnorrGroupFromParams(p, g, q)
}

func LoadQR(name string) *dlog.QR {
	x := viper.GetStringMap(name)
	p, _ := new(big.Int).SetString(x["p"].(string), 10)
	q, _ := new(big.Int).SetString(x["q"].(string), 10)
	factors := []*big.Int{p, q}
	return dlog.NewQR(factors)
}

func LoadPseudonymsysOrgSecrets(orgName, dlogType string) (*big.Int, *big.Int) {
	org := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", orgName, dlogType))
	s1, _ := new(big.Int).SetString(org["s1"].(string), 10)
	s2, _ := new(big.Int).SetString(org["s2"].(string), 10)
	return s1, s2
}

func LoadPseudonymsysOrgPubKeys(orgName string) (*big.Int, *big.Int) {
	org := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", orgName, "dlog"))
	h1, _ := new(big.Int).SetString(org["h1"].(string), 10)
	h2, _ := new(big.Int).SetString(org["h2"].(string), 10)
	return h1, h2
}

func LoadPseudonymsysOrgPubKeysEC(orgName string) (*big.Int, *big.Int, *big.Int, *big.Int) {
	org := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", orgName, "ecdlog"))
	h1X, _ := new(big.Int).SetString(org["h1x"].(string), 10)
	h1Y, _ := new(big.Int).SetString(org["h1y"].(string), 10)
	h2X, _ := new(big.Int).SetString(org["h2x"].(string), 10)
	h2Y, _ := new(big.Int).SetString(org["h2y"].(string), 10)
	return h1X, h1Y, h2X, h2Y
}

func LoadPseudonymsysCASecret() *big.Int {
	ca := viper.GetStringMap("pseudonymsys.ca")
	s, _ := new(big.Int).SetString(ca["d"].(string), 10)
	return s
}

func LoadPseudonymsysCAPubKey() (*big.Int, *big.Int) {
	ca := viper.GetStringMap("pseudonymsys.ca")
	x, _ := new(big.Int).SetString(ca["x"].(string), 10)
	y, _ := new(big.Int).SetString(ca["y1"].(string), 10)
	return x, y
}

func LoadServiceInfo() *types.ServiceInfo {
	serviceName := viper.GetString("service_info.name")
	serviceProvider := viper.GetString("service_info.provider")
	serviceDescription := viper.GetString("service_info.description")
	return types.NewServiceInfo(serviceName, serviceProvider, serviceDescription)
}

func LoadSessionKeyMinByteLen() int {
	return viper.GetInt("session_key_bytelen")
}

func LoadRegistrationDBAddress() string {
	return viper.GetString("registration_db_address")
}
