# OPC-UA Device Service

## Overview
This repository is a Go-based EdgeX Foundry Device Service 2.1.0 which uses OPC-UA protocol to interact with the devices or IoT objects.

## Feature

1. Subscribe data from OPCUA endpoint
2. Execute read command
3. Execute write command
4. Prometheus monitoring
![image](https://user-images.githubusercontent.com/80612608/143887940-d0bafa14-752f-46b6-a8a5-241f4efde87f.png)
![image](https://user-images.githubusercontent.com/80612608/143888050-311dd5f3-d88e-4c80-9c56-6e9c2114622e.png)


## Prerequisite
* Edgex-go: core data, core command, core metadata
* OPCUA Server

## Predefined configuration

### Pre-define Devices
Define devices for device-sdk to auto upload device profile and create device instance. Please modify `configuration.toml` file which under `./cmd/res` folder
```toml
# Pre-define Devices
[[DeviceList]]
  Name = "SimulationServer"
  Profile = "OPCUA-Server"
  Description = "OPCUA device is created for test purpose"
  Labels = [ "test" ]
  [DeviceList.Protocols]
      [DeviceList.Protocols.opcua]
          Endpoint = "opc.tcp://192.168.2.134:53530/OPCUA/SimulationServer"
          Policy = "None"                   # Security policy: None, Basic128Rsa15, Basic256, Basic256Sha256. Default: auto
          Mode = "None"                     # Security mode: None, Sign, SignAndEncrypt. Default: auto
          CertFile = ""                     # Path to cert.pem. Required for security mode/policy != None
          KeyFile = ""                      # Path to private key.pem. Required for security mode/policy != None
          Event="false"
          Interval="5000"
```

### Subscribe configuration
Modify `configuration.toml` file which under `./cmd/res` folder if needed
```toml

```
## Devic Profile

A Device Profile can be thought of as a template of a type or classification of Device. 

Write device profile for your own devices, difine deviceResources, deviceCommands and coreCommands. Please refer to `cmd/res/profiles/prosys-test.yaml`

Tips: name in deviceResources should consistent with OPCUA nodeid


## Installation and Execution
```bash
make build
make run
```

## docker image
edgego/device-opcua:2.1.0

## Reference
* EdgeX Foundry Services: https://github.com/edgexfoundry/edgex-go
* Go OPCUA library: https://github.com/gopcua/opcua
* OPCUA Server: https://www.prosysopc.com/products/opc-ua-simulation-server
