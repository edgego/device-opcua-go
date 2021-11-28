package driver

import (
	"context"
	"fmt"
	"github.com/edgexfoundry/device-sdk-go/v2/pkg/service"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/errors"
	coreModels "github.com/edgexfoundry/go-mod-core-contracts/v2/models"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"sync"
)

type Executor struct {
	ctx          context.Context
	cancel       context.CancelFunc
	deviceName   string
	stop         bool
	mutex        *sync.Mutex
	client       *opcua.Client
	deviceSource coreModels.DeviceResource
	opcInfo      *OpcuaInfo
}

// Run triggers this Executor executes the handler for the subecribe source periodically
func (e *Executor) Run() {
	err := subscribeResource(e.ctx,e.deviceName ,e.opcInfo ,e.client ,e.deviceSource)
	if err != nil {
		driver.Logger.Errorf("AutoSubcribe - error occurs when reading resource %s: %v", e.deviceSource.Name, err)
	}
}

// Stop marks this Executor stopped
func (e *Executor) Stop() {
	e.stop = true
	driver.Logger.Debug("Stop - send cancel signal to cancel all go routines that reading resources ")
	e.cancel()
}

// NewExecutor creates an Executor for an AutoEvent
func NewExecutor(deviceName string, dr coreModels.DeviceResource) (*Executor, errors.EdgeX) {
	ds := service.RunningService()
	device, err := ds.GetDeviceByName(deviceName)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("device not found: %s",deviceName))

		return nil,errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprint("device not found: %s",deviceName), err)
	}

	opcInfo, err := CreateOpcuaInfo(device.Protocols)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("Create Opcua info failed: %s ",err))
		return nil,errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprintf("Create Opcua info failed: %s ",err), err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	endpoints, err := opcua.GetEndpoints(ctx,opcInfo.Endpoint)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("GetEndpoints failed: %s ",err))
		return nil,errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprintf("GetEndpoints failed: %s ",err), err)
	}

	ep := opcua.SelectEndpoint(endpoints, opcInfo.Policy, ua.MessageSecurityModeFromString(opcInfo.Mode))
	ep.EndpointURL = opcInfo.Endpoint
	if ep == nil {
		driver.Logger.Error(fmt.Sprintf("Failed to find suitable endpoint: %s ",err))
		return nil,errors.NewCommonEdgeX(errors.KindContractInvalid, fmt.Sprintf("Failed to find suitable endpoint: %s ",err), err)
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

	return &Executor{
		ctx:          ctx,
		cancel:       cancel,
		deviceName:   deviceName,
		deviceSource: dr,
		stop:         false,
		opcInfo:      opcInfo,
		client:       client,
		mutex:        &sync.Mutex{}}, nil
}
