/*
SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"

	api "github.com/flant/machine-controller-manager-provider-yandex/pkg/provider/apis"
	corev1 "k8s.io/api/core/v1"

	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/yandex-cloud/go-sdk/iamkey"
)

type SecretUIDToYcSDK map[types.UID]*ycsdk.SDK

type YandexSessionStore struct {
	sync.Mutex

	sdk SecretUIDToYcSDK
}

func NewYandexSession() *YandexSessionStore {
	return &YandexSessionStore{
		sdk: make(SecretUIDToYcSDK),
	}
}

func (ys *YandexSessionStore) GetSession(ctx context.Context, secret *corev1.Secret) (*ycsdk.SDK, error) {
	ys.Lock()
	defer ys.Unlock()

	if sdk, ok := ys.sdk[secret.UID]; ok {
		return sdk, nil
	}

	var serviceAccountKey iamkey.Key
	err := json.Unmarshal(secret.Data[api.YandexServiceAccountJSON], &serviceAccountKey)
	if err != nil {
		return nil, err
	}

	creds, err := ycsdk.ServiceAccountKey(&serviceAccountKey)
	if err != nil {
		return nil, err
	}

	return ycsdk.Build(ctx, ycsdk.Config{Credentials: creds})
}

func (ys *YandexSessionStore) GC() {
	ys.Lock()
	defer ys.Unlock()

	ctx, cancelFunc := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelFunc()

	for k, v := range ys.sdk {
		_ = v.Shutdown(ctx)
		delete(ys.sdk, k)
	}
}
