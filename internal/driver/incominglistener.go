// Package driver
// Copyright (C) 2021~2040 EdgeGo
//
// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"fmt"
	"github.com/edgexfoundry/device-sdk-go/v2/pkg/service"
	"time"

	"github.com/edgexfoundry/device-sdk-go/v2/pkg/models"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
)

func startIncomingListening(deviceName string) error {

	ds := service.RunningService()
	device, err := ds.GetDeviceByName(deviceName)
	if err != nil {
		err = fmt.Errorf("device not found: %s", deviceName)
		return err
	}

	opcInfo, err := CreateOpcuaInfo(device.Protocols)
	if err != nil {
		return err
	}

	ctx := context.Background()

	endpoints, err := opcua.GetEndpoints(opcInfo.Endpoint)
	if err != nil {
		return err
	}

	ep := opcua.SelectEndpoint(endpoints, opcInfo.Policy, ua.MessageSecurityModeFromString(opcInfo.Mode))
	// replace Burning-Laptop with ip adress
	ep.EndpointURL = opcInfo.Endpoint
	if ep == nil {
		return fmt.Errorf("Failed to find suitable endpoint")
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
		return err
	}

	defer client.Close()

	sub, err := client.Subscribe(&opcua.SubscriptionParameters{
		Interval: 500 * time.Millisecond,
	})
	if err != nil {
		return err
	}
	defer sub.Cancel()

	id, err := ua.ParseNodeID(opcInfo.NodeID)
	if err != nil {
		return err
	}

	// arbitrary client handle for the monitoring item
	handle := uint32(1) // arbitrary client id
	miCreateRequest := opcua.NewMonitoredItemCreateRequestWithDefaults(id, ua.AttributeIDValue, handle)
	res, err := sub.Monitor(ua.TimestampsToReturnBoth, miCreateRequest)
	if err != nil || res.Results[0].StatusCode != ua.StatusOK {
		return err
	}

	driver.Logger.Info("[Incoming listener] Start incoming data listening. ")

	go sub.Run(ctx) // start Publish loop

	// read from subscription's notification channel until ctx is cancelled
	for {
		select {
		// context return
		case <-ctx.Done():
			return nil
			// receive Publish Notification Data
		case res := <-sub.Notifs:
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
			}
		}
	}

	return nil
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