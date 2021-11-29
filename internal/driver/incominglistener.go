// Package driver
// Copyright (C) 2021~2040 EdgeGo
//
// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"fmt"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/errors"
	"time"

	"github.com/edgexfoundry/device-sdk-go/v2/pkg/models"
	"github.com/edgexfoundry/device-sdk-go/v2/pkg/service"
	coreModels "github.com/edgexfoundry/go-mod-core-contracts/v2/models"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
)

var (
	resourceReadCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "resource_read_counts",
			Help: "How many read resource requests processed, partitioned by device name, resource name.",
		},
		[]string{"service", "device", "resource"},
	)

	resourceReadResponse = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "resource_read_response_bytes",
			Help: "Response data from device , partitioned by device name, resource name.",
		},
		[]string{"service", "device", "resource"},
	)
)

func subscribeResource(ctx context.Context,deviceName string,opcInfo *OpcuaInfo,client *opcua.Client,dr coreModels.DeviceResource) error{
	if _, ok := dr.Attributes[NAMESPACEINDEX]; !ok {
		return  errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprintf("attribute %s not exists", NAMESPACEINDEX), nil)
	}

	if _, ok := dr.Attributes[IDENTIFIER]; !ok {
		return  errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprintf("attribute %s not exists", IDENTIFIER), nil)
	}

	if _, ok := dr.Attributes[SUBSCRIBE]; !ok {
		driver.Logger.Info(fmt.Sprintf("Device : [%v] resource : [%v] running mode is not subscribing mode ...",deviceName,dr.Name))

		return nil
	}

	ns :=  uint32(dr.Attributes[NAMESPACEINDEX].(float64))
	identifier := uint32(dr.Attributes[IDENTIFIER].(float64))
	subscribe := dr.Attributes[SUBSCRIBE].(bool)

	driver.Logger.Debug(fmt.Sprintf("Subscribe resource: [%v],namespace index: [%v], identifier: [%v], subscribe mode : [%v]",dr.Name, ns,identifier,subscribe))

	if subscribe == false{
		driver.Logger.Info(fmt.Sprintf("Device : [%v] resource : [%v] running mode is not subscribing mode ...",deviceName,dr.Name))
		return nil
	}

	notifyCh := make(chan *opcua.PublishNotificationData)

	if opcInfo.Interval <= 0  {
		opcInfo.Interval = 500
	}
	interval := time.Duration(opcInfo.Interval) * time.Millisecond;

	if err := client.Connect(ctx); err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to connect opcua endpoint: %s ",err))
		return fmt.Errorf(fmt.Sprintf("Failed to connect opcua endpoint: %s ",err))
	}

	sub, err := client.Subscribe(&opcua.SubscriptionParameters{
		Interval: interval,
	}, notifyCh)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to Subscribe opcua server: %s ",err))
		return err
	}

	driver.Logger.Debug(fmt.Sprintf("Created subscription with id %v", sub.SubscriptionID))

	nodeId := "ns=" + fmt.Sprint(ns) + ";i=" + fmt.Sprint(identifier)
	id, err := ua.ParseNodeID(nodeId)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to ParseNodeID: %s ",err))
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
		driver.Logger.Error(fmt.Sprintf("Monitor failed: %T ",err))
		return err
	}

	defer client.Close()
	defer sub.Cancel()

	driver.Logger.Info(fmt.Sprintf("[Incoming listener] device : [%s], resource :[%s] Start incoming data listening... ",deviceName,dr.Name))

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
					driver.Logger.Debug(fmt.Sprintf("MonitoredItem with client handle %v, value = %v", item.ClientHandle,data))
					onIncomingDataReceived(deviceName,dr.Name,data)
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

func onIncomingDataReceived(deviceName string,resourceName string ,data interface{}) {

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
