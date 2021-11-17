// Package driver
// Copyright (C) 2021~2040 EdgeGo
//
// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"fmt"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/errors"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/models"
	"reflect"
	"strconv"
)

type Configuration struct {
	Writable WritableInfo
	//OpcuaInfo OpcuaInfo
}

type OpcuaInfo struct {
	Endpoint     	string
	Policy 			string
	Mode  			string
	CertFile	 	string
	KeyFile 		string
	NodeID 			string
	Event			bool
	Interval        int32
}

type WritableInfo struct {
	ResponseFetchInterval int
}

// Validate ensures your custom configuration has proper values.
func (info *OpcuaInfo) Validate() errors.EdgeX {

	return nil
}

func (sw *OpcuaInfo) UpdateFromRaw(rawConfig interface{}) bool {
	configuration, ok := rawConfig.(*OpcuaInfo)
	if !ok {
		return false //errors.New("unable to cast raw config to type 'ServiceConfig'")
	}

	*sw = *configuration
	return true
}

// CreateOpcuaInfo use to load opcua Info for read and write command
func CreateOpcuaInfo(protocols map[string]models.ProtocolProperties) (*OpcuaInfo, error) {
	info := new(OpcuaInfo)
	protocol, ok := protocols["opcua"]
	if !ok {
		return info, fmt.Errorf("unable to load config, 'opcua' not exist")
	}

	err := load(protocol, info)
	if err != nil {
		return info, err
	}
	return info, nil
}

// loadOpcuaConfig loads the opcua  configuration
func loadOpcuaConfig(configMap map[string]string) (*Configuration, error) {
	config := new(Configuration)
	err := load(configMap, config)
	if err != nil {
		return config, err
	}
	return config, nil
}

// load by reflect to check map key and then fetch the value
func load(config map[string]string, des interface{}) error {
	errorMessage := "unable to load config, '%s' not exist"
	val := reflect.ValueOf(des).Elem()
	for i := 0; i < val.NumField(); i++ {
		typeField := val.Type().Field(i)
		valueField := val.Field(i)

		val, ok := config[typeField.Name]
		if !ok {
			return fmt.Errorf(errorMessage, typeField.Name)
		}

		switch valueField.Kind() {
		case reflect.Int:
			intVal, err := strconv.Atoi(val)
			if err != nil {
				return err
			}
			valueField.SetInt(int64(intVal))
		case reflect.Bool:
			boolVal, err := strconv.ParseBool(val)
			if err != nil {
				return err
			}
			valueField.SetBool(boolVal)
		case reflect.String:
			valueField.SetString(val)
		default:
			return fmt.Errorf("none supported value type %v ,%v", valueField.Kind(), typeField.Name)
		}
	}
	return nil
}
