// Copyright © 2015 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

// Package remote integrates the remote features of Viper.
package remote

import (
	"bytes"
	"io"
	"os"

	"strings"

	"github.com/0987363/viper"
	crypt "github.com/0987363/crypt/config"
)

type remoteConfigProvider struct{}

func (rc remoteConfigProvider) Get(rp viper.RemoteProvider) (io.Reader, error) {
	cm, err := getConfigManager(rp)
	if err != nil {
		return nil, err
	}
	b, err := cm.Get(rp.Path())
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

func (rc remoteConfigProvider) Watch(rp viper.RemoteProvider) (io.Reader, error) {
	cm, err := getConfigManager(rp)
	if err != nil {
		return nil, err
	}
	resp, err := cm.Get(rp.Path())
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(resp), nil
}

func (rc remoteConfigProvider) WatchChannel(rp viper.RemoteProvider) (<-chan *viper.RemoteResponse, chan bool) {
	cm, err := getConfigManager(rp)
	if err != nil {
		return nil, nil
	}
	quit := make(chan bool)
	quitwc := make(chan bool)
	viperResponsCh := make(chan *viper.RemoteResponse)
	cryptoResponseCh := cm.Watch(rp.Path(), quit)
	// need this function to convert the Channel response form crypt.Response to viper.Response
	go func(cr <-chan *crypt.Response, vr chan<- *viper.RemoteResponse, quitwc <-chan bool, quit chan<- bool) {
		for {
			select {
			case <-quitwc:
				quit <- true
				return
			case resp := <-cr:
				vr <- &viper.RemoteResponse{
					Error: resp.Error,
					Value: resp.Value,
				}

			}

		}
	}(cryptoResponseCh, viperResponsCh, quitwc, quit)

	return viperResponsCh, quitwc
}

func getConfigManager(rp viper.RemoteProvider) (crypt.ConfigManager, error) {
	var cm crypt.ConfigManager
	var err error

	if rp.SecretKeyring() != "" {
		kr, err := os.Open(rp.SecretKeyring())
		defer kr.Close()
		if err != nil {
			return nil, err
		}
		switch rp.Provider() {
		case "etcdv3":
			cm, err = crypt.NewEtcdv3ConfigManager(toMachines(rp.Endpoint()), kr)
		case "etcd":
			cm, err = crypt.NewEtcdConfigManager(toMachines(rp.Endpoint()), kr)
		default:
			cm, err = crypt.NewConsulConfigManager(toMachines(rp.Endpoint()), kr)
		}
	} else {
		switch rp.Provider() {
		case "etcdv3":
			cm, err = crypt.NewStandardEtcdv3ConfigManager(toMachines(rp.Endpoint()))
		case "etcd":
			cm, err = crypt.NewStandardEtcdConfigManager(toMachines(rp.Endpoint()))
		default:
			cm, err = crypt.NewStandardConsulConfigManager(toMachines(rp.Endpoint()))
		}
	}
	if err != nil {
		return nil, err
	}
	return cm, nil
}

func toMachines(endpoint string) []string {
	machines := strings.Split(endpoint, ",")
	return machines
}

func init() {
	viper.RemoteConfig = &remoteConfigProvider{}
}
