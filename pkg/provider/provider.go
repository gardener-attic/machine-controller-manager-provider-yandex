/*
SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
SPDX-License-Identifier: Apache-2.0
*/

// Package provider contains the cloud provider specific implementations to manage machines
package provider

import (
	"github.com/flant/machine-controller-manager-provider-yandex/pkg/spi"
	"github.com/gardener/machine-controller-manager/pkg/util/provider/driver"
)

type Provider struct {
	YandexSDK *spi.YandexSessionStore
}

// NewProvider returns an empty provider object
func NewProvider() driver.Driver {
	return &Provider{
		YandexSDK: spi.NewYandexSession(),
	}
}
