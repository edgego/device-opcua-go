// Package driver
// Copyright (C) 2021~2040 EdgeGo
//
// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"fmt"
	"time"

	"github.com/edgexfoundry/device-sdk-go/v2/pkg/models"
	"github.com/edgexfoundry/device-sdk-go/v2/pkg/service"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
)

func startIncomingListening(deviceName string,ds *service.DeviceService) error {

	device, err := ds.GetDeviceByName(deviceName)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("device not found: %s",deviceName))
		return err
	}

	opcInfo, err := CreateOpcuaInfo(device.Protocols)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Create Opcua info failed: %s ",err))
		return err
	}

	ctx := context.Background()

	endpoints, err := opcua.GetEndpoints(ctx,opcInfo.Endpoint)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("GetEndpoints failed: %s ",err))
		return err
	}

	ep := opcua.SelectEndpoint(endpoints, opcInfo.Policy, ua.MessageSecurityModeFromString(opcInfo.Mode))
	ep.EndpointURL = opcInfo.Endpoint
	if ep == nil {
		driver.Logger.Error(fmt.Sprintf("Failed to find suitable endpoint: %s ",err))
		return err
	}

	opts := []opcua.Option{
		opcua.SecurityPolicy(opcInfo.Policy),
		opcua.SecurityModeString(opcInfo.Mode),
		opcua.CertificateFile(opcInfo.CertFile),
		opcua.PrivateKeyFile(opcInfo.KeyFile),
		opcua.AuthAnonymous(),
		opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
	}

	client := opcua.NewClient(ep.EndpointURL, opts...)
	if err := client.Connect(ctx); err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to connect opcua endpoint: %s ",err))
		return err
	}
	defer client.Close()

	notifyCh := make(chan *opcua.PublishNotificationData)

	if opcInfo.Interval <= 0  {
		opcInfo.Interval = 500
	}
	interval := time.Duration(opcInfo.Interval) * time.Millisecond;

	sub, err := client.Subscribe(&opcua.SubscriptionParameters{
		Interval: interval,
	}, notifyCh)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to Subscribe opcua server: %s ",err))
		return err
	}

	defer sub.Cancel()
	driver.Logger.Info(fmt.Sprintf("Created subscription with id %v", sub.SubscriptionID))

	nodeId, err := ua.ParseNodeID(opcInfo.NodeID)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to ParseNodeID: %s ",err))
		return err
	}

	//parse node id to browser name
	nodeInfo := client.Node(nodeId)
	attr, err := nodeInfo.Attributes( ua.AttributeIDBrowseName)
	if err != nil  && attr[0].Status != ua.StatusOK {
		driver.Logger.Error(fmt.Sprintf("Failed to get browser name: %s ",err))
		return err
	}
	browserName := attr[0].Value.String()

	var miCreateRequest *ua.MonitoredItemCreateRequest
	var eventFieldNames []string

	if opcInfo.Event {
		miCreateRequest, eventFieldNames = eventRequest(nodeId)
	} else {
		miCreateRequest = valueRequest(nodeId)
	}
	res, err := sub.Monitor(ua.TimestampsToReturnBoth, miCreateRequest)
	if err != nil || res.Results[0].StatusCode != ua.StatusOK {
		driver.Logger.Error(fmt.Sprintf("Monitor failed: %T ",err))
		return err
	}

	driver.Logger.Info("[Incoming listener] Start incoming data listening. ")

	for {
		select {
		case <-ctx.Done():
			return nil
		case res := <-notifyCh:
			if res.Error != nil {
				driver.Logger.Error(fmt.Sprintf("%s", res.Error))
				continue
			}
			switch x := res.Value.(type) {
			case *ua.DataChangeNotification:
				for _, item := range x.MonitoredItems {
					data := item.Value.Value.Value()
					driver.Logger.Debug(fmt.Sprintf("MonitoredItem with client handle %v value = %v", item.ClientHandle, data))
					onIncomingDataReceived(device.Name,browserName,data)
				}
			case *ua.EventNotificationList:
				for _, item := range x.Events {
					driver.Logger.Debug(fmt.Sprintf("Event for client handle: %v\n", item.ClientHandle))
					for i, field := range item.EventFields {
						driver.Logger.Debug(fmt.Sprintf("%v: %v of Type: %T", eventFieldNames[i], field.Value(), field.Value()))
					}
				}

			default:
				driver.Logger.Debug(fmt.Sprintf("what's this publish result? %T", res.Value))
			}
		}
	}

	return nil
}


func valueRequest(nodeID *ua.NodeID) *ua.MonitoredItemCreateRequest {
	handle := uint32(42)
	return opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, handle)
}

func eventRequest(nodeID *ua.NodeID) (*ua.MonitoredItemCreateRequest, []string) {
	fieldNames := []string{"EventId", "EventType", "Severity", "Time", "Message"}
	selects := make([]*ua.SimpleAttributeOperand, len(fieldNames))

	for i, name := range fieldNames {
		selects[i] = &ua.SimpleAttributeOperand{
			TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
			BrowsePath:       []*ua.QualifiedName{{NamespaceIndex: 0, Name: name}},
			AttributeID:      ua.AttributeIDValue,
		}
	}

	wheres := &ua.ContentFilter{
		Elements: []*ua.ContentFilterElement{
			{
				FilterOperator: ua.FilterOperatorGreaterThanOrEqual,
				FilterOperands: []*ua.ExtensionObject{
					{
						EncodingMask: 1,
						TypeID: &ua.ExpandedNodeID{
							NodeID: ua.NewNumericNodeID(0, id.SimpleAttributeOperand_Encoding_DefaultBinary),
						},
						Value: ua.SimpleAttributeOperand{
							TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
							BrowsePath:       []*ua.QualifiedName{{NamespaceIndex: 0, Name: "Severity"}},
							AttributeID:      ua.AttributeIDValue,
						},
					},
					{
						EncodingMask: 1,
						TypeID: &ua.ExpandedNodeID{
							NodeID: ua.NewNumericNodeID(0, id.LiteralOperand_Encoding_DefaultBinary),
						},
						Value: ua.LiteralOperand{
							Value: ua.MustVariant(uint16(0)),
						},
					},
				},
			},
		},
	}

	filter := ua.EventFilter{
		SelectClauses: selects,
		WhereClause:   wheres,
	}

	filterExtObj := ua.ExtensionObject{
		EncodingMask: ua.ExtensionObjectBinary,
		TypeID: &ua.ExpandedNodeID{
			NodeID: ua.NewNumericNodeID(0, id.EventFilter_Encoding_DefaultBinary),
		},
		Value: filter,
	}

	handle := uint32(42)
	req := &ua.MonitoredItemCreateRequest{
		ItemToMonitor: &ua.ReadValueID{
			NodeID:       nodeID,
			AttributeID:  ua.AttributeIDEventNotifier,
			DataEncoding: &ua.QualifiedName{},
		},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle:     handle,
			DiscardOldest:    true,
			Filter:           &filterExtObj,
			QueueSize:        10,
			SamplingInterval: 1.0,
		},
	}

	return req, fieldNames
}

func onIncomingDataReceived(deviceName string,resourceName string,data interface{}) {

	reading := data

	ds := service.RunningService()

	deviceResource, ok := ds.DeviceResource(deviceName, resourceName)
	if !ok {
		driver.Logger.Error(fmt.Sprintf("[Incoming listener] Incoming reading ignored. No DeviceResource found: name=%v deviceResource=%v value=%v", deviceName, resourceName, data))
		return
	}

	req := models.CommandRequest{
		DeviceResourceName: resourceName,
		Type:               deviceResource.Properties.ValueType,
	}

	result, err := newResult(req, reading)

	if err != nil {
		driver.Logger.Error(fmt.Sprintf("[Incoming listener] Incoming reading ignored. name=%v deviceResource=%v value=%v,error=%v", deviceName, resourceName, data,err))
		return
	}

	asyncValues := &models.AsyncValues{
		DeviceName:    deviceName,
		CommandValues: []*models.CommandValue{result},
	}

	driver.Logger.Debug(fmt.Sprintf("[Incoming listener] Incoming reading received: name=%v deviceResource=%v value=%v", deviceName, resourceName, data))

	driver.AsyncCh <- asyncValues

}
