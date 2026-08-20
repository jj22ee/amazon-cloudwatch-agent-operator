// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package instrumentation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/rest"
)

func TestShouldClaimEKSPlatform(t *testing.T) {
	tests := []struct {
		name      string
		detect    func() (bool, error)
		k8sMode   string
		wantClaim bool
	}{
		{
			name:      "detected EKS claims the platform",
			detect:    func() (bool, error) { return true, nil },
			k8sMode:   "EKS",
			wantClaim: true,
		},
		{
			// The case this change exists for: a native-K8s cluster where the chart left
			// k8sMode at its EKS default. Detection must win so the SDK yields "k8s:",
			// matching what the CloudWatch agent independently resolves.
			name:      "detected non-EKS overrides a stale k8sMode=EKS",
			detect:    func() (bool, error) { return false, nil },
			k8sMode:   "EKS",
			wantClaim: false,
		},
		{
			name:      "detected EKS claims the platform even when k8sMode says K8S",
			detect:    func() (bool, error) { return true, nil },
			k8sMode:   "K8S",
			wantClaim: true,
		},
		{
			name:      "detected non-EKS with k8sMode=K8S stays generic",
			detect:    func() (bool, error) { return false, nil },
			k8sMode:   "K8S",
			wantClaim: false,
		},
		{
			name:      "inconclusive detection falls back to k8sMode=EKS",
			detect:    func() (bool, error) { return false, errors.New("no token") },
			k8sMode:   "EKS",
			wantClaim: true,
		},
		{
			name:      "inconclusive detection falls back to k8sMode=K8S",
			detect:    func() (bool, error) { return false, errors.New("no token") },
			k8sMode:   "K8S",
			wantClaim: false,
		},
		{
			name:      "inconclusive detection with empty k8sMode stays generic",
			detect:    func() (bool, error) { return false, errors.New("no token") },
			k8sMode:   "",
			wantClaim: false,
		},
		{
			name:      "k8sMode fallback is case-insensitive",
			detect:    func() (bool, error) { return false, errors.New("no token") },
			k8sMode:   "eks",
			wantClaim: true,
		},
	}

	original := detectEKS
	t.Cleanup(func() { detectEKS = original })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detectEKS = tt.detect
			assert.Equal(t, tt.wantClaim, shouldClaimEKSPlatform(tt.k8sMode))
		})
	}
}

func TestHasEKSCredentialEnvVars(t *testing.T) {
	tests := []struct {
		name string
		envs map[string]string
		want bool
	}{
		{
			name: "IRSA token file indicates EKS",
			envs: map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"},
			want: true,
		},
		{
			name: "Pod Identity token file indicates EKS",
			envs: map[string]string{"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": "/var/run/secrets/pods.eks-pod-identity/token"},
			want: true,
		},
		{
			name: "unrelated web identity token file does not indicate EKS",
			envs: map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/other/token"},
			want: false,
		},
		{
			name: "no env vars set",
			envs: nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envs {
				t.Setenv(k, v)
			}
			assert.Equal(t, tt.want, hasEKSCredentialEnvVars())
		})
	}
}

func TestServiceAccountTokenIssuer(t *testing.T) {
	jwtWithIssuer := func(issuer string) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
		payload, _ := json.Marshal(map[string]string{"iss": issuer})
		return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	}

	tests := []struct {
		name       string
		config     func() (*rest.Config, error)
		wantIssuer string
		wantErr    bool
	}{
		{
			name: "EKS OIDC issuer is returned",
			config: func() (*rest.Config, error) {
				return &rest.Config{BearerToken: jwtWithIssuer("https://oidc.eks.us-east-1.amazonaws.com/id/ABC123")}, nil
			},
			wantIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/ABC123",
		},
		{
			name: "native K8s issuer is returned",
			config: func() (*rest.Config, error) {
				return &rest.Config{BearerToken: jwtWithIssuer("https://kubernetes.default.svc.cluster.local")}, nil
			},
			wantIssuer: "https://kubernetes.default.svc.cluster.local",
		},
		{
			name:    "in-cluster config error",
			config:  func() (*rest.Config, error) { return nil, errors.New("not in cluster") },
			wantErr: true,
		},
		{
			name:    "empty bearer token",
			config:  func() (*rest.Config, error) { return &rest.Config{}, nil },
			wantErr: true,
		},
		{
			name:    "token is not a JWT",
			config:  func() (*rest.Config, error) { return &rest.Config{BearerToken: "not-a-jwt"}, nil },
			wantErr: true,
		},
		{
			name: "payload is not valid JSON",
			config: func() (*rest.Config, error) {
				bad := base64.RawURLEncoding.EncodeToString([]byte("{not json"))
				return &rest.Config{BearerToken: "hdr." + bad + ".sig"}, nil
			},
			wantErr: true,
		},
		{
			name: "payload has no issuer claim",
			config: func() (*rest.Config, error) {
				payload, _ := json.Marshal(map[string]string{"sub": "system:serviceaccount:x:y"})
				return &rest.Config{BearerToken: "hdr." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"}, nil
			},
			wantErr: true,
		},
	}

	original := getInClusterConfig
	t.Cleanup(func() { getInClusterConfig = original })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getInClusterConfig = tt.config
			issuer, err := serviceAccountTokenIssuer()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantIssuer, issuer)
		})
	}
}
