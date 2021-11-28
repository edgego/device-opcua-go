// Package driver
// Copyright (C) 2021~2040 EdgeGo
//
// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"fmt"
	sdkModel "github.com/edgexfoundry/device-sdk-go/v2/pkg/models"
	"github.com/edgexfoundry/device-sdk-go/v2/pkg/service"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/common"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/errors"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/models"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"

	"github.com/spf13/cast"
	"sync"
)

var once sync.Once
var driver *Driver

type Driver struct {
	Logger           logger.LoggingClient
	AsyncCh          chan<- *sdkModel.AsyncValues
	CommandResponses sync.Map
	DriverConfig    *Configuration
	Manager         *manager
}

func NewProtocolDriver() sdkModel.ProtocolDriver {
	once.Do(func() {
		driver = new(Driver)
	})
	return driver
}

func (d *Driver) AddDevice(deviceName string, protocols map[string]models.ProtocolProperties, adminState models.AdminState) error {
	d.Logger.Debugf("Device %s is added", deviceName)

	if adminState == "UNLOCKED"{
		d.Manager.RestartForDevice(deviceName)
	}

	return nil
}

func (d *Driver) UpdateDevice(deviceName string, protocols map[string]models.ProtocolProperties, adminState models.AdminState) error {
	d.Logger.Debugf("Device %s is updated", deviceName)

	if adminState == "UNLOCKED"{
		d.Manager.RestartForDevice(deviceName)
	}

	return nil
}

func (d *Driver) RemoveDevice(deviceName string, protocols map[string]models.ProtocolProperties) error {
	d.Logger.Debugf("Device %s is removed", deviceName)

	d.Manager.StopForDevice(deviceName)

	return nil
}

// Initialize performs protocol-specific initialization for the device service.
func (d *Driver) Initialize(lc logger.LoggingClient, asyncCh chan<- *sdkModel.AsyncValues, deviceCh chan<- []sdkModel.DiscoveredDevice) error {
	d.Logger = lc
	d.AsyncCh = asyncCh

	/*

	//read opc-ua driver configuration
	opcuaConfig, err := loadOpcuaConfig(service.DriverConfigs())
	if err != nil {
		driver.Logger.Errorf("load opc-ua configuration failed: %v", err)
	}
	d.DriverConfig = opcuaConfig

	ctx, _ := context.WithCancel(context.Background())

	//defer cancel()

	//start  listening opcua devices
	ds := service.RunningService()
	d.Logger.Debug(fmt.Sprintf("Devices information : %v,devices length :%d", ds.Devices(), len(ds.Devices())))
	for _, device := range ds.Devices() {
		startIncomingListening(ctx,device.Name,ds)
	}*/

	ds := service.RunningService()
	d.Logger.Debug(fmt.Sprintf("Devices information : %v,devices length :%d", ds.Devices(), len(ds.Devices())))
	buffSize := 256

	if ds.AsyncReadings(){
		buffSize = 256
	}

	//ctx, _ := context.WithCancel(context.Background())

	m := &manager{
		executorMap:      make(map[string][]*Executor),
		subscriberBuffer: make(chan bool, buffSize),
	}

	d.Manager = m

    m.StartSubscribingEvents()

	return nil
}

func (d *Driver) DisconnectDevice(deviceName string, protocols map[string]models.ProtocolProperties) error {
	d.Logger.Warn("Driver's DisconnectDevice function")

	d.Manager.StopForDevice(deviceName)

	return nil
}

// HandleReadCommands triggers a protocol Read operation for the specified device.
func (d *Driver) HandleReadCommands(deviceName string, protocols map[string]models.ProtocolProperties,
	reqs []sdkModel.CommandRequest) ([]*sdkModel.CommandValue, error) {

	d.Logger.Debug(fmt.Sprintf("Driver.HandleReadCommands: device: %v ,protocols: %v, resource: %v, attributes: %v", deviceName, protocols, reqs[0].DeviceResourceName, reqs[0].Attributes))
	var responses = make([]*sdkModel.CommandValue, len(reqs))
	var err error

	// create device client and open connection
	opcuaInfo, err := CreateOpcuaInfo(protocols)
	if err != nil {
		d.Logger.Error(fmt.Sprintf("Driver.HandleReadCommands: createing OpcuaInfo falied: %v", err))
		return nil,err
	}

	ctx := context.Background()

	endpoints, err := opcua.GetEndpoints(ctx,opcuaInfo.Endpoint)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("GetEndpoints failed: %s ",err))
		return nil,err
	}

	ep := opcua.SelectEndpoint(endpoints, opcuaInfo.Policy, ua.MessageSecurityModeFromString(opcuaInfo.Mode))
	ep.EndpointURL = opcuaInfo.Endpoint
	if ep == nil {
		driver.Logger.Error(fmt.Sprintf("Failed to find suitable endpoint: %s ",err))
		return nil,err
	}

	opts := []opcua.Option{
		opcua.SecurityPolicy(opcuaInfo.Policy),
		opcua.SecurityModeString(opcuaInfo.Mode),
		opcua.CertificateFile(opcuaInfo.CertFile),
		opcua.PrivateKeyFile(opcuaInfo.KeyFile),
		opcua.AuthAnonymous(),
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
	}

	client := opcua.NewClient(ep.EndpointURL, opts...)
	if err := client.Connect(ctx); err != nil {
		d.Logger.Error(fmt.Sprintf("Driver.HandleReadCommands: connecting opc us server falied: %v", err))
		return responses, err
	}

	for i, req := range reqs {
		// handle every reqs
		d.Logger.Debug(fmt.Sprintf("Driver.handleReadCommands: Begin to process reqs = %v", req))

		res, err := d.handleReadCommandRequest(client,req)
		if err != nil {
			driver.Logger.Error(fmt.Sprintf("Driver.HandleReadCommands: Handle read commands failed: %v", err))
			return responses, err
		}
		responses[i] = res
	}

	defer client.Close()

	return responses, err
}

func (d *Driver) handleReadCommandRequest(client *opcua.Client,
	req sdkModel.CommandRequest) (*sdkModel.CommandValue, error) {
	var result = &sdkModel.CommandValue{}
	var err error

	/*
	ns, err := strconv.Atoi(namespace)
	if err != nil {
		return nil,fmt.Errorf(fmt.Sprintf("Driver.handleReadCommandRequest: convert namespace to int %s failed : %v",namespace, err))
	}

	root := client.Node(ua.NewTwoByteNodeID(opcuaConst.ObjectsFolder))
	id, err := root.TranslateBrowsePathInNamespaceToNodeID(uint16(ns), "Simulation."+ req.DeviceResourceName)
	if err != nil {
		d.Logger.Error(fmt.Sprintf("Driver.handleReadCommandRequest: get nodeId with namespace :%s command name %s failed : %v",namespace,req.DeviceResourceName, err))
		return nil,fmt.Errorf(fmt.Sprintf("Driver.handleReadCommandRequest: get nodeId with command name %s failed : %v",req.DeviceResourceName, err))
	}

	driver.Logger.Debug(fmt.Sprintf("Driver.handleReadCommandRequest: get nodeId : %v, with namespace :%s resource %s",id,namespace,req.DeviceResourceName))
	driver.Logger.Debug(fmt.Sprintf("Driver.handleReadCommandRequest: parse nodeId : %v",id.String()))

	nodeId, err := ua.ParseNodeID(id.String())
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to ParseNodeID: %s ",err))
		return nil,err
	}
	 */

	if _, ok := req.Attributes[NAMESPACEINDEX]; !ok {
		return nil, errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprintf("attribute %s not exists", NAMESPACEINDEX), nil)
	}

	if _, ok := req.Attributes[IDENTIFIER]; !ok {
		return nil, errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprintf("attribute %s not exists", IDENTIFIER), nil)
	}

	ns :=  uint32(req.Attributes[NAMESPACEINDEX].(float64))
	identifier := uint32(req.Attributes[IDENTIFIER].(float64))

	d.Logger.Debug(fmt.Sprintf("Driver.handleReadCommands: ns = [%v], identifier = [%v]", ns,identifier))

	nodeId := "ns=" + fmt.Sprint(ns) + ";i=" + fmt.Sprint(identifier)
	id, err := ua.ParseNodeID(nodeId)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to ParseNodeID: %s ",err))
		return nil,err
	}

	//make and execute ReadRequest
	request := &ua.ReadRequest{
		MaxAge: 2000,
		NodesToRead: []*ua.ReadValueID{
			{NodeID: id},
		},
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	}

	resp, err := client.Read(request)
	if err != nil {
		d.Logger.Error(fmt.Sprintf("Driver.handleReadCommands: Read failed: %s", err))
		return nil, err
	}
	if resp.Results[0].Status != ua.StatusOK {
		d.Logger.Error(fmt.Sprintf("Driver.handleReadCommands: Status not OK: %v", resp.Results[0].Status))
		return nil, err
	}

	// make new result
	reading := resp.Results[0].Value.Value()
	result, err = newResult(req, reading)
	if err != nil {
		return result, err
	} else {
		d.Logger.Info(fmt.Sprintf("Get command finished: %v", result))
	}

	return result, err
}

// HandleWriteCommands passes a slice of CommandRequest struct each representing
// a ResourceOperation for a specific device resource (aka DeviceObject).
// Since the commands are actuation commands, params provide parameters for the individual
// command.
func (d *Driver) HandleWriteCommands(deviceName string, protocols map[string]models.ProtocolProperties,
	reqs []sdkModel.CommandRequest, params []*sdkModel.CommandValue) error {

	driver.Logger.Debug(fmt.Sprintf("OpcUaDriver.HandleWriteCommands: protocols: %v, resource: %v, parameters: %v", protocols, reqs[0].DeviceResourceName, params))
	var err error

	// create device client and open connection
	opcuaInfo, err := CreateOpcuaInfo(protocols)
	if err != nil {
		d.Logger.Error(fmt.Sprintf("Driver.HandleWriteCommands: createing OpcuaInfo falied: %v", err))
		return err
	}

	ctx := context.Background()

	endpoints, err := opcua.GetEndpoints(ctx,opcuaInfo.Endpoint)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("GetEndpoints failed: %s ",err))
		return err
	}

	ep := opcua.SelectEndpoint(endpoints, opcuaInfo.Policy, ua.MessageSecurityModeFromString(opcuaInfo.Mode))
	ep.EndpointURL = opcuaInfo.Endpoint
	if ep == nil {
		driver.Logger.Error(fmt.Sprintf("Failed to find suitable endpoint: %s ",err))
		return err
	}

	opts := []opcua.Option{
		opcua.SecurityPolicy(opcuaInfo.Policy),
		opcua.SecurityModeString(opcuaInfo.Mode),
		opcua.CertificateFile(opcuaInfo.CertFile),
		opcua.PrivateKeyFile(opcuaInfo.KeyFile),
		opcua.AuthAnonymous(),
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
	}

	client := opcua.NewClient(ep.EndpointURL, opts...)
	if err := client.Connect(ctx); err != nil {
		d.Logger.Error(fmt.Sprintf("Driver.HandleReadCommands: connecting opc us server falied: %v", err))
		return err
	}

	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		d.Logger.Warn(fmt.Sprintf("Driver.HandleWriteCommands: Failed to create OPCUA client, %s", err))
		return  err
	}

	for _, req := range reqs {
		// handle every reqs every params
		for _, param := range params {
			err := d.handleWeadCommandRequest(client, req, param)
			if err != nil {
				d.Logger.Error(fmt.Sprintf("Driver.HandleWriteCommands: Handle write commands failed: %v", err))
				return  err
			}
		}

	}

	return err
}

func (d *Driver) handleWeadCommandRequest(deviceClient *opcua.Client, req sdkModel.CommandRequest,
	param *sdkModel.CommandValue) error {
	var err error

	if _, ok := req.Attributes[NAMESPACEINDEX]; !ok {
		return errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprintf("attribute %s not exists", NAMESPACEINDEX), nil)
	}

	if _, ok := req.Attributes[IDENTIFIER]; !ok {
		return errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprintf("attribute %s not exists", IDENTIFIER), nil)
	}

	ns :=  uint32(req.Attributes[NAMESPACEINDEX].(float64))
	identifier := uint32(req.Attributes[IDENTIFIER].(float64))

	d.Logger.Debug(fmt.Sprintf("Driver.handleWeadCommandRequest: ns = [%v], identifier = [%v]", ns,identifier))

	nodeId := "ns=" + fmt.Sprint(ns) + ";i=" + fmt.Sprint(identifier)
	id, err := ua.ParseNodeID(nodeId)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to ParseNodeID: %s ",err))
		return err
	}

	value, err := newCommandValue(req.Type, param)
	if err != nil {
		d.Logger.Errorf(fmt.Sprintf("Driver.newCommandValue: Invalid node id=%v", err))
		return err
	}
	v, err := ua.NewVariant(value)

	if err != nil {
		d.Logger.Errorf(fmt.Sprintf("Driver.handleWriteCommands: invalid value: %v", err))
		return fmt.Errorf(fmt.Sprintf("Driver.handleWriteCommands: invalid value: %v", err))
	}

	request := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			&ua.WriteValue{
				NodeID:      id,
				AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{
					EncodingMask: uint8(6),  // encoding mask
					Value:        v,
				},
			},
		},
	}

	resp, err := deviceClient.Write(request)
	if err != nil {
		d.Logger.Error(fmt.Sprintf("Driver.handleWriteCommands: Write value %v failed: %s", v, err))
		return err
	}
	d.Logger.Info(fmt.Sprintf("Driver.handleWriteCommands: write sucessfully, ", resp.Results[0]))

	return nil
}


// Stop the protocol-specific DS code to shutdown gracefully, or
// if the force parameter is 'true', immediately. The driver is responsible
// for closing any in-use channels, including the channel used to send async
// readings (if supported).
func (d *Driver) Stop(force bool) error {
	d.Logger.Warn("Driver's Stop function didn't implement")
	return nil
}

func newResult(req sdkModel.CommandRequest, reading interface{}) (*sdkModel.CommandValue, error) {
	var result = &sdkModel.CommandValue{}
	var err error
	castError := "fail to parse %v reading, %v"

	if !checkValueInRange(req.Type, reading) {
		err = fmt.Errorf("parse reading fail. Reading %v is out of the value type(%v)'s range", reading, req.Type)
		driver.Logger.Errorf("parse reading fail. Reading %v is out of the value type(%v)'s range", reading, req.Type)
		return result, err
	}

	//driver.Logger.Info(req.Type)
	switch req.Type {
	case common.ValueTypeBool:
		val, err := cast.ToBoolE(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeString:
		val, err := cast.ToStringE(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeUint8:
		val, err := cast.ToUint8E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeUint16:
		val, err := cast.ToUint16E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeUint32:
		val, err := cast.ToUint32E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeUint64:
		val, err := cast.ToUint64E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeInt8:
		val, err := cast.ToInt8E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeInt16:
		val, err := cast.ToInt16E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeInt32:
		val, err := cast.ToInt32E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeInt64:
		val, err := cast.ToInt64E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeFloat32:
		val, err := cast.ToFloat32E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	case common.ValueTypeFloat64:
		val, err := cast.ToFloat64E(reading)
		if err != nil {
			return nil, fmt.Errorf(castError, req.DeviceResourceName, err)
		}
		result, err = sdkModel.NewCommandValue(req.DeviceResourceName, req.Type , val)
	default:
		err = fmt.Errorf("return result fail, none supported value type: %v", req.Type)
	}

	return result, err
}


func newCommandValue(valueType string, param *sdkModel.CommandValue) (interface{}, error) {
	var commandValue interface{}
	var err error
	switch valueType {
	case common.ValueTypeBool:
		commandValue, err = param.BoolValue()
	case common.ValueTypeString:
		commandValue, err = param.StringValue()
	case common.ValueTypeUint8:
		commandValue, err = param.Uint8Value()
	case common.ValueTypeUint16:
		commandValue, err = param.Uint16Value()
	case common.ValueTypeUint32:
		commandValue, err = param.Uint32Value()
	case common.ValueTypeUint64:
		commandValue, err = param.Uint64Value()
	case common.ValueTypeInt8:
		commandValue, err = param.Int8Value()
	case common.ValueTypeInt16:
		commandValue, err = param.Int16Value()
	case common.ValueTypeInt32:
		commandValue, err = param.Int32Value()
	case common.ValueTypeInt64:
		commandValue, err = param.Int64Value()
	case common.ValueTypeFloat32:
		commandValue, err = param.Float32Value()
	case common.ValueTypeFloat64:
		commandValue, err = param.Float64Value()
	default:
		err = fmt.Errorf("fail to convert param, none supported value type: %v", valueType)
	}

	return commandValue, err
}
