// Package driver
// Copyright (C) 2021~2040 EdgeGo
//
// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"fmt"
	"github.com/edgexfoundry/device-sdk-go/v2/pkg/service"
	"github.com/gopcua/opcua/id"
	"time"

	"github.com/edgexfoundry/device-sdk-go/v2/pkg/models"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
)

func startIncomingListening(deviceName string) error {

	ds := service.RunningService()
	device, err := ds.GetDeviceByName(deviceName)
	if err != nil {
		driver.Logger.Info(fmt.Sprintf("device not found: %s",deviceName))
		return err
	}

	opcInfo, err := CreateOpcuaInfo(device.Protocols)
	if err != nil {
		driver.Logger.Info(fmt.Sprintf("Create Opcua info failed: %s ",err))
		return err
	}

	ctx := context.Background()

	endpoints, err := opcua.GetEndpoints(ctx,opcInfo.Endpoint)
	if err != nil {
		driver.Logger.Info(fmt.Sprintf("GetEndpoints failed: %s ",err))
		return err
	}

	ep := opcua.SelectEndpoint(endpoints, opcInfo.Policy, ua.MessageSecurityModeFromString(opcInfo.Mode))
	ep.EndpointURL = opcInfo.Endpoint
	if ep == nil {
		driver.Logger.Info(fmt.Sprintf("Failed to find suitable endpoint: %s ",err))
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
		driver.Logger.Info(fmt.Sprintf("Failed to connect opcua endpoint: %s ",err))
		return err
	}
	defer client.Close()

	notifyCh := make(chan *opcua.PublishNotificationData)

	sub, err := client.Subscribe(&opcua.SubscriptionParameters{
		Interval: 500 * time.Millisecond,
	}, notifyCh)
	if err != nil {
		driver.Logger.Info(fmt.Sprintf("Failed to Subscribe opcua server: %s ",err))
		return err
	}

	defer sub.Cancel()
	driver.Logger.Info(fmt.Sprintf("Created subscription with id %v", sub.SubscriptionID))

	id, err := ua.ParseNodeID(opcInfo.NodeID)
	if err != nil {
		driver.Logger.Info(fmt.Sprintf("Failed to ParseNodeID: %s ",err))
		return err
	}

	var miCreateRequest *ua.MonitoredItemCreateRequest
	var eventFieldNames []string
	
	if opcInfo.Event {
		miCreateRequest, eventFieldNames = eventRequest(id)
	} else {
		miCreateRequest = valueRequest(id)
	}
	res, err := sub.Monitor(ua.TimestampsToReturnBoth, miCreateRequest)
	if err != nil || res.Results[0].StatusCode != ua.StatusOK {
		driver.Logger.Info(fmt.Sprintf("Monitor failed: %T ",err))
		return err
	}

	driver.Logger.Info("[Incoming listener] Start incoming data listening. ")

	// read from subscription's notification channel until ctx is cancelled
	for {
		select {
		// context return
		case <-ctx.Done():
			return nil
			// receive Publish Notification Data
		case res := <-notifyCh:
			if res.Error != nil {
				driver.Logger.Debug(fmt.Sprintf("%s", res.Error))
				continue
			}
			switch x := res.Value.(type) {
			// result type: DateChange StatusChange
			case *ua.DataChangeNotification:
				for _, item := range x.MonitoredItems {
					data := item.Value.Value.Value
					onIncomingDataReceived(device.Name,opcInfo,data)
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

func onIncomingDataReceived(deviceName string,opcInfo *OpcuaInfo,data interface{}) {

	resourceName := opcInfo.NodeID
	reading := data

	ds := service.RunningService()

	deviceObject, ok := ds.DeviceResource(deviceName, resourceName)
	if !ok {
		driver.Logger.Warn(fmt.Sprintf("[Incoming listener] Incoming reading ignored. No DeviceObject found: name=%v deviceResource=%v value=%v", deviceName, resourceName, data))
		return
	}

	req := models.CommandRequest{
		DeviceResourceName: resourceName,
		Type:               deviceObject.Properties.ValueType,
	}

	result, err := newResult(req, reading)

	if err != nil {
		driver.Logger.Warn(fmt.Sprintf("[Incoming listener] Incoming reading ignored. name=%v deviceResource=%v value=%v", deviceName, resourceName, data))
		return
	}

	asyncValues := &models.AsyncValues{
		DeviceName:    deviceName,
		CommandValues: []*models.CommandValue{result},
	}

	driver.Logger.Info(fmt.Sprintf("[Incoming listener] Incoming reading received: name=%v deviceResource=%v value=%v", deviceName, resourceName, data))

	driver.AsyncCh <- asyncValues

}
