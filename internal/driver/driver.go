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
	"log"
	"sync"
)

var once sync.Once
var lock sync.Mutex
var driver *Driver
var clients map[string]opcua.Client

type Driver struct {
	Logger           logger.LoggingClient
	AsyncCh          chan<- *sdkModel.AsyncValues
	CommandResponses sync.Map
	serviceConfig    *Configuration
}

func NewProtocolDriver() sdkModel.ProtocolDriver {
	once.Do(func() {
		driver = new(Driver)
		clients = make(map[string]opcua.Client)
	})
	return driver
}

func (d *Driver) AddDevice(deviceName string, protocols map[string]models.ProtocolProperties, adminState models.AdminState) error {
	d.Logger.Debugf("Device %s is added", deviceName)
	_, err := d.addrFromProtocols(protocols)
	if err != nil {
		err = fmt.Errorf("error adding device: %w", err)
		d.Logger.Error(err.Error())
		return err
	}

	opcuaConfig, err := CreateOpcuaInfo(protocols)
	if err != nil {
		return fmt.Errorf("while add device, failed to create cameraInfo for device %s: %w", deviceName, err)
	}

	_, err = d.clientsFromOpcuaConfig(opcuaConfig, deviceName)
	if err != nil {
		err = fmt.Errorf("error adding device: %w", err)
		d.Logger.Error(err.Error())
		return err
	}

	return nil
}

func (d *Driver) UpdateDevice(deviceName string, protocols map[string]models.ProtocolProperties, adminState models.AdminState) error {
	d.Logger.Debugf("Device %s is updated", deviceName)
	return nil
}

func shutdownClient(addr string) {
	lock.Lock()

	if client, ok := clients[addr]; ok {
		client.Close()
		delete(clients, addr)
	}

	lock.Unlock()
}

func (d *Driver) RemoveDevice(deviceName string, protocols map[string]models.ProtocolProperties) error {
	d.Logger.Debugf("Device %s is removed", deviceName)
	addr, err := d.addrFromProtocols(protocols)
	if err != nil {
		return fmt.Errorf("no address found for device: %w", err)
	}

	shutdownClient(addr)
	return nil
}

func getClient(addr string) (opcua.Client, bool) {
	lock.Lock()
	c, ok := clients[addr]
	lock.Unlock()
	return c, ok
}

func newClient(device models.Device, serviceConfig *OpcuaInfo) *opcua.Client {

	var endpoint = serviceConfig.Endpoint
	var policy     = serviceConfig.Policy
	var mode       = serviceConfig.Mode
	var certFile   = serviceConfig.CertFile
	var keyFile    = serviceConfig.KeyFile
	//var nodeID     = serviceConfig.OpcuaServer.NodeID

	ctx := context.Background()
	endpoints, err := opcua.GetEndpoints(endpoint)
	if err != nil {
		return nil
	}
	ep := opcua.SelectEndpoint(endpoints, policy, ua.MessageSecurityModeFromString(mode))
	// replace Burning-Laptop with ip adress
	ep.EndpointURL = endpoint
	if ep == nil {
		return nil
	}

	opts := []opcua.Option{
		opcua.SecurityPolicy(policy),
		opcua.SecurityModeString(mode),
		opcua.CertificateFile(certFile),
		opcua.PrivateKeyFile(keyFile),
		opcua.AuthAnonymous(),
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
	}

	client := opcua.NewClient(ep.EndpointURL, opts...)
	if err := client.Connect(ctx); err != nil {
		return nil
	}

	addr := device.Protocols[OPCUA][ENDPOINT]
	lock.Lock()
	clients[addr] = *client
	lock.Unlock()

	return client
}

func (d *Driver) clientsFromOpcuaConfig(serviceConfig *OpcuaInfo, deviceName string) ( *opcua.Client, error) {
	client, ok := getClient(serviceConfig.Endpoint)

	if !ok {
		dev, err := service.RunningService().GetDeviceByName(deviceName)
		if err != nil {
			err = fmt.Errorf("device not found: %s", deviceName)
			d.Logger.Error(err.Error())

			return  nil, err
		}

		client = * newClient(dev, serviceConfig)
		lock.Lock()
		clients[serviceConfig.Endpoint] = client
		lock.Unlock()
	}

	return &client, nil
}

// Initialize performs protocol-specific initialization for the device service.
func (d *Driver) Initialize(lc logger.LoggingClient, asyncCh chan<- *sdkModel.AsyncValues, deviceCh chan<- []sdkModel.DiscoveredDevice) error {
	d.Logger = lc
	d.AsyncCh = asyncCh

	//read opc-ua driver configuration
	opcuaConfig, err := loadOpcuaConfig(service.DriverConfigs())
	if err != nil {
		panic(fmt.Errorf("load opc-ua configuration failed: %w", err))
	}
	d.serviceConfig = opcuaConfig

	//start  listening opcua devices
	ds := service.RunningService()
	for _, device := range ds.Devices() {
		go func() {
			err := startIncomingListening(device.Name)
			if err != nil {
				panic(fmt.Errorf("Driver.Initialize: Start incoming data Listener failed: %v", err))
			}
		}()
	}

	return nil
}

func (d *Driver) DisconnectDevice(deviceName string, protocols map[string]models.ProtocolProperties) error {
	d.Logger.Warn("Driver's DisconnectDevice function")
	addr, err := d.addrFromProtocols(protocols)
	if err != nil {
		return fmt.Errorf("no address found for device: %w", err)
	}

	shutdownClient(addr)
	return nil
}

func (d *Driver) addrFromProtocols(protocols map[string]models.ProtocolProperties) (string, error) {
	if _, ok := protocols[OPCUA]; !ok {
		d.Logger.Error("No OPCUA protocol found for device. Check configuration file.")
		return "", errors.NewCommonEdgeX(errors.KindUnknown, "o OPCUA protocol in protocols map", nil)
	}

	var addr string
	addr, ok := protocols[OPCUA][ENDPOINT]
	if !ok {
		d.Logger.Error("No OPCUA endpoint found for device. Check configuration file.")
		return "", errors.NewCommonEdgeX(errors.KindUnknown, "o OPCUA endpoint in protocols map", nil)
	}
	return addr, nil
}

// HandleReadCommands triggers a protocol Read operation for the specified device.
func (d *Driver) HandleReadCommands(deviceName string, protocols map[string]models.ProtocolProperties,
	reqs []sdkModel.CommandRequest) ([]*sdkModel.CommandValue, error) {

	driver.Logger.Debug(fmt.Sprintf("Driver.HandleReadCommands: protocols: %v resource: %v attributes: %v", protocols, reqs[0].DeviceResourceName, reqs[0].Attributes))
	var responses = make([]*sdkModel.CommandValue, len(reqs))
	var err error

	_, err = d.addrFromProtocols(protocols)
	if err != nil {
		return responses, fmt.Errorf("handleReadCommands: %w", err)
	}

	// create device client and open connection
	opcuaInfo, err := CreateOpcuaInfo(protocols)
	if err != nil {
		return nil,err
	}

	// check for existence of both clients
	client, err := d.clientsFromOpcuaConfig(opcuaInfo, deviceName)
	if err != nil {
		return responses, fmt.Errorf("handleReadCommands: %w", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	for i, req := range reqs {
		// handle every reqs
		res, err := d.handleReadCommandRequest(client, req)
		if err != nil {
			driver.Logger.Error(fmt.Sprintf("Driver.HandleReadCommands: Handle read commands failed: %v", err))
			return responses, err
		}
		responses[i] = res
	}

	return responses, err
}

func (d *Driver) handleReadCommandRequest(deviceClient *opcua.Client,
	req sdkModel.CommandRequest) (*sdkModel.CommandValue, error) {
	var result = &sdkModel.CommandValue{}
	var err error
	nodeID := req.DeviceResourceName

	// get NewNodeID
	id, err := ua.ParseNodeID(nodeID)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Driver.handleReadCommands: Invalid node id=%s", nodeID))
		return result, err
	}

	// make and execute ReadRequest
	request := &ua.ReadRequest{
		MaxAge: 2000,
		NodesToRead: []*ua.ReadValueID{
			&ua.ReadValueID{NodeID: id},
		},
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	}
	resp, err := deviceClient.Read(request)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Driver.handleReadCommands: Read failed: %s", err))
	}
	if resp.Results[0].Status != ua.StatusOK {
		driver.Logger.Error(fmt.Sprintf("Driver.handleReadCommands: Status not OK: %v", resp.Results[0].Status))
	}

	// make new result
	reading := resp.Results[0].Value.Value
	result, err = newResult(req, reading)
	if err != nil {
		return result, err
	} else {
		driver.Logger.Info(fmt.Sprintf("Get command finished: %v", result))
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

	_, err = d.addrFromProtocols(protocols)
	if err != nil {
		return fmt.Errorf("handleWriteCommands: %w", err)
	}

	// create device client and open connection
	opcuaInfo, err := CreateOpcuaInfo(protocols)
	if err != nil {
		return fmt.Errorf("Failed to create opcua device %s: %w",deviceName, err)
	}

	// check for existence of both clients
	client, err := d.clientsFromOpcuaConfig(opcuaInfo, deviceName)
	if err != nil {
		return fmt.Errorf("handleReadCommands: %w", err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		driver.Logger.Warn(fmt.Sprintf("Driver.HandleWriteCommands: Failed to create OPCUA client, %s", err))
		return  err
	}

	for _, req := range reqs {
		// handle every reqs every params
		for _, param := range params {
			err := d.handleWeadCommandRequest(client, req, param)
			if err != nil {
				driver.Logger.Error(fmt.Sprintf("Driver.HandleWriteCommands: Handle write commands failed: %v", err))
				return  err
			}
		}

	}

	return err
}

func (d *Driver) handleWeadCommandRequest(deviceClient *opcua.Client, req sdkModel.CommandRequest,
	param *sdkModel.CommandValue) error {
	var err error
	nodeID := req.DeviceResourceName

	// get NewNodeID
	id, err := ua.ParseNodeID(nodeID)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Driver.handleWriteCommands: Invalid node id=%s", nodeID))
	}

	value, err := newCommandValue(req.Type, param)
	if err != nil {
		return err
	}
	v, err := ua.NewVariant(value)

	if err != nil {
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
		driver.Logger.Error(fmt.Sprintf("Driver.handleWriteCommands: Write value %v failed: %s", v, err))
		return err
	}
	driver.Logger.Info(fmt.Sprintf("Driver.handleWriteCommands: write sucessfully, ", resp.Results[0]))
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
		driver.Logger.Error(err.Error())
		return result, err
	}

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
