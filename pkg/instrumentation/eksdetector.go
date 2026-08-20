// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package instrumentation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"k8s.io/client-go/rest"
)

// EKS detection, ported from the CloudWatch agent's translator/util/eksdetector so the operator
// claims the EKS platform based on the SAME runtime signal the agent uses, rather than the static
// Helm .Values.k8sMode. The agent's Application Signals resolver decides its "eks:" vs "k8s:"
// Environment prefix purely from this detection (DetectKubernetesMode -> IsEKS), so mirroring it
// here keeps the operator-injected cloud.platform — and therefore the SDK's resolved
// aws.local.environment — consistent with Application Signals on every cluster type, with no
// operator- or chart-level configuration required.
//
// Detection (cached once per process, mirroring the agent's sync.Once):
//  1. Fast path, no I/O: IRSA / Pod Identity environment variables.
//  2. Fallback: parse the in-cluster ServiceAccount token as a JWT and test whether its "iss"
//     (OIDC issuer) claim contains "eks".
//
// Known limitations, shared with the agent's detector (and therefore NOT a source of divergence —
// where this is wrong, the agent is wrong the same way, so the two still agree):
//   - An EKS cluster with a custom/BYO OIDC issuer whose URL lacks "eks" reads as non-EKS.
//   - A self-managed cluster whose issuer URL happens to contain "eks" reads as EKS.
//   - If the ServiceAccount token is unreadable, detection is inconclusive; callers fall back to
//     the configured K8S_MODE.
const (
	// serviceAccountTokenIssuerMarker is the substring the agent looks for in the OIDC issuer.
	serviceAccountTokenIssuerMarker = "eks"

	irsaTokenFileMarker        = "eks.amazonaws.com"
	podIdentityTokenFileMarker = "eks-pod-identity"
)

var (
	eksDetectOnce  sync.Once
	eksDetectValue bool
	eksDetectErr   error

	// detectEKS is a package variable so tests can stub the detection result.
	detectEKS = isEKS

	// getInClusterConfig is a package variable so tests can stub the in-cluster config.
	getInClusterConfig = func() (*rest.Config, error) { return rest.InClusterConfig() }
)

// isEKS reports whether this process appears to run on EKS. The returned error is non-nil when
// detection was inconclusive (no readable ServiceAccount token), in which case the boolean is
// meaningless and callers should fall back to their configured mode. Result is cached.
func isEKS() (bool, error) {
	eksDetectOnce.Do(func() {
		if hasEKSCredentialEnvVars() {
			eksDetectValue, eksDetectErr = true, nil
			return
		}
		issuer, err := serviceAccountTokenIssuer()
		if err != nil {
			eksDetectValue, eksDetectErr = false, err
			return
		}
		eksDetectValue = strings.Contains(strings.ToLower(issuer), serviceAccountTokenIssuerMarker)
		eksDetectErr = nil
	})
	return eksDetectValue, eksDetectErr
}

// hasEKSCredentialEnvVars checks the IRSA and Pod Identity environment variables, which are set
// only on EKS. Cheap, no I/O.
func hasEKSCredentialEnvVars() bool {
	if strings.Contains(os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"), irsaTokenFileMarker) {
		return true
	}
	return strings.Contains(os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"), podIdentityTokenFileMarker)
}

// serviceAccountTokenIssuer returns the "iss" claim of the in-cluster ServiceAccount token.
func serviceAccountTokenIssuer() (string, error) {
	conf, err := getInClusterConfig()
	if err != nil {
		return "", fmt.Errorf("failed to get in-cluster config: %w", err)
	}
	if conf.BearerToken == "" {
		return "", errors.New("empty bearer token in in-cluster config")
	}

	parts := strings.Split(conf.BearerToken, ".")
	if len(parts) < 2 {
		return "", errors.New("service account token is not a JWT: missing payload")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims map[string]interface{}
	if err = json.Unmarshal(decoded, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal token payload: %w", err)
	}
	issuer, ok := claims["iss"].(string)
	if !ok {
		return "", errors.New("issuer claim not found in service account token")
	}
	return issuer, nil
}

// shouldClaimEKSPlatform reports whether to inject cloud.platform=aws_eks. Runtime detection is
// authoritative so the injected platform always matches what the CloudWatch agent independently
// detects; the configured K8S_MODE is used only when detection is inconclusive, preserving the
// operator's previous behavior as a safety net.
func shouldClaimEKSPlatform(k8sMode string) bool {
	if onEKS, err := detectEKS(); err == nil {
		return onEKS
	}
	return strings.EqualFold(k8sMode, k8sModeEKS)
}
