/*
SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
SPDX-License-Identifier: Apache-2.0
*/

package api

import corev1 "k8s.io/api/core/v1"

const (
	YandexFolderID           string = "folderID"
	YandexServiceAccountJSON string = "serviceAccountJSON"
)

// ProviderSpec is the spec to be used while parsing the calls.
type YandexProviderSpec struct {
	APIVersion string `json:"apiVersion,omitempty"`

	Labels     map[string]string `json:"labels,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	RegionID   string            `json:"regionID,omitempty"`
	ZoneID     string            `json:"zoneID,omitempty"`
	PlatformID string            `json:"platformID,omitempty"`

	ResourcesSpec         YandexProviderSpecResourcesSpec           `json:"resourcesSpec,omitempty"`
	BootDiskSpec          YandexProviderSpecBootDiskSpec            `json:"bootDiskSpec,omitempty"`
	NetworkInterfaceSpecs []YandexProviderSpecNetworkInterfaceSpecs `json:"networkInterfaceSpecs,omitempty"`
	SchedulingPolicy      YandexProviderSpecSchedulingPolicy        `json:"schedulingPolicy,omitempty"`

	SecretRef *corev1.SecretReference `json:"secretRef,omitempty"`
}

type YandexProviderSpecResourcesSpec struct {
	Cores        int64 `json:"cores,omitempty"`
	CoreFraction int64 `json:"coreFraction,omitempty"`
	Memory       int64 `json:"memory,omitempty"`
	GPUs         int64 `json:"gpus,omitempty"`
}

type YandexProviderSpecBootDiskSpec struct {
	AutoDelete bool   `json:"autoDelete,omitempty"`
	TypeID     string `json:"typeID,omitempty"`
	Size       int64  `json:"size,omitempty"`
	ImageID    string `json:"imageID,omitempty"`
}

type YandexProviderSpecNetworkInterfaceSpecs struct {
	SubnetID              string   `json:"subnetID,omitempty"`
	AssignPublicIPAddress bool     `json:"assignPublicIPAddress,omitempty"`
	PublicIPAddresses     []string `json:"publicIPAddresses,omitempty"`
}

type YandexProviderSpecSchedulingPolicy struct {
	Preemptible bool `json:"preemptible,omitempty"`
}
