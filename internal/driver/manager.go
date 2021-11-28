package driver

import (
	"fmt"
	"sync"

	"github.com/edgexfoundry/device-sdk-go/v2/pkg/service"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/models"
)

type manager struct {
	executorMap        map[string][]*Executor
	mutex              sync.Mutex
	subscriberBuffer   chan bool
}

func (m *manager) StartSubscribingEvents() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	ds := service.RunningService()
	driver.Logger.Debug(fmt.Sprintf("Devices information : %v,devices length :%d", ds.Devices(), len(ds.Devices())))

	for _, device := range ds.Devices() {
		profile, err := ds.GetProfileByName(device.ProfileName)
		if  err != nil {
			driver.Logger.Error(fmt.Sprintf("Failed to get profile with name: [%s], error: %v ",device.ProfileName,err))
			continue
		}

		resources := profile.DeviceResources
		driver.Logger.Debug(fmt.Sprintf("DeviceResources information : %v,DeviceResources length :%d", resources, len(resources)))
		if _, ok := m.executorMap[device.Name]; !ok {
			executors := m.triggerExecutors(device.Name, resources)
			m.executorMap[device.Name] = executors
		}
	}
}

func (m *manager) triggerExecutors(deviceName string, resources []models.DeviceResource) []*Executor {
	var executors []*Executor

	for _, resource := range resources {
		driver.Logger.Debug(fmt.Sprintf("[triggerExecutors] DeviceResource information [%v]",resource))
		executor, err := NewExecutor(deviceName, resource)
		if err != nil {
			driver.Logger.Errorf(fmt.Sprintf("failed to create executor of AutoSubscribeEvent %s for Device [%s] Resource [%s] : %v",deviceName, resource.Name, err))
			continue
		}
		executors = append(executors, executor)
		go executor.Run()
	}

	return executors
}

func (m *manager) RestartForDevice(deviceName string) {

	m.StopForDevice(deviceName)

	ds := service.RunningService()
	device, err := ds.GetDeviceByName(deviceName)
	if err != nil {
		driver.Logger.Error(fmt.Sprintf("device not found: %s",deviceName))
		return
	}

	profile, err := ds.GetProfileByName(device.ProfileName)
	if  err != nil {
		driver.Logger.Error(fmt.Sprintf("Failed to get profile with name: [%s], error: %v ",device.ProfileName,err))
		return
	}
	resources := profile.DeviceResources

	m.mutex.Lock()
	defer m.mutex.Unlock()
	executors := m.triggerExecutors(deviceName,resources)
	m.executorMap[deviceName] = executors
}

func (m *manager) StopForDevice(deviceName string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	executors, ok := m.executorMap[deviceName]
	if ok {
		for _, executor := range executors {
			executor.Stop()
		}
		delete(m.executorMap, deviceName)
	}
}
