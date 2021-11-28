// Package driver
// Copyright (C) 2021~2040 EdgeGo
//
// SPDX-License-Identifier: Apache-2.0
package driver

// Constants related to protocol properties
const (
	Protocol     = "opcua"
)

// Constants related to custom configuration
const (
	CustomConfigSectionName = "OpcuaServer"
	OPCUA                   = "opcua"
	ENDPOINT                = "Endpoint"
	NODEID				    = "NodeID"
	WritableInfoSectionName = CustomConfigSectionName + "/Writable"
	NAMESPACEINDEX          ="ns"
	IDENTIFIER              ="identifier"
	SUBSCRIBE               ="subscribe"
)
