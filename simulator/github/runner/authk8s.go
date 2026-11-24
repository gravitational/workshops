package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// tbotAudience is the audience tbot requests for its GitHub ID token.
const tbotAudience = "teleport.cluster.local"

// authK8s emulates teleport-actions/auth-k8s.
//
// It does what the real action does (same tbot config, env, outputs and KUBECONFIG export)
// but runs the preinstalled tbot, and first logs the ID token's claims so the demo can
// show what Teleport is about to check.
type authK8s struct{ tbot string }

func (a authK8s) Run(ctx context.Context, sc *StepContext) error {
	sc.Log("Simulated teleport-actions/auth-k8s: running the preinstalled tbot with the configuration the real action writes")
	if envLookup(sc.Env, "ACTIONS_ID_TOKEN_REQUEST_URL") == "" {
		return errors.New(`ACTIONS_ID_TOKEN_REQUEST_URL is not set; add "permissions: id-token: write" to the job`)
	}
	with := trimmedInputs(sc.With)
	for _, name := range []string{"kubernetes-cluster", "proxy", "token"} {
		if with[name] == "" {
			return fmt.Errorf("Input required and not supplied: %s", name)
		}
	}

	runnerTemp := envLookup(sc.Env, "RUNNER_TEMP")
	if runnerTemp == "" {
		runnerTemp = os.TempDir()
	}
	dest, err := os.MkdirTemp(runnerTemp, "")
	if err != nil {
		return err
	}
	config, err := authK8sConfig(with, dest)
	if err != nil {
		return err
	}
	configPath, err := writeTbotConfig(runnerTemp, config)
	if err != nil {
		return err
	}

	a.logIDTokenClaims(ctx, sc)

	sc.Log("Invoking tbot with configuration at " + configPath)
	if _, err := runTool(ctx, sc, tbotEnv(sc.Env, with), a.tbot, "start", "-c", configPath); err != nil {
		return err
	}

	kubeconfig := filepath.Join(dest, "kubeconfig.yaml")
	sc.SetOutput("destination-dir", dest)
	sc.SetOutput("identity-file", filepath.Join(dest, "identity"))
	sc.SetOutput("kubeconfig", kubeconfig)
	if !stringToBool(with["disable-env-vars"]) {
		sc.ExportEnv("KUBECONFIG", kubeconfig)
	}
	return nil
}

// trimmedInputs mirrors core.getInput, which trims every input.
func trimmedInputs(with map[string]string) map[string]string {
	out := make(map[string]string, len(with))
	for k, v := range with {
		out[k] = strings.TrimSpace(v)
	}
	return out
}

var truthy = regexp.MustCompile(`(?i)^\s*(true|1)\s*$`)

func stringToBool(s string) bool { return truthy.MatchString(s) }

// authK8sConfig is the tbot configuration the real action writes
// (baseConfigurationFromSharedInputs plus its kubernetes output).
func authK8sConfig(with map[string]string, destDir string) (map[string]any, error) {
	caPins := []string{}
	for line := range strings.SplitSeq(with["ca-pins"], "\n") {
		if pin := strings.TrimSpace(line); pin != "" {
			caPins = append(caPins, pin)
		}
	}
	cfg := map[string]any{
		"version":      "v2",
		"proxy_server": with["proxy"],
		"oneshot":      true,
		"onboarding": map[string]any{
			"join_method": "github",
			"token":       with["token"],
			"ca_pins":     caPins,
		},
		"storage": map[string]any{"type": "memory"},
		"outputs": []any{
			map[string]any{
				"type": "kubernetes",
				"destination": map[string]any{
					"type":     "directory",
					"symlinks": "try-secure",
					"path":     destDir,
				},
				"roles":              []string{},
				"kubernetes_cluster": with["kubernetes-cluster"],
			},
		},
		"services": []any{},
	}
	if ttl := with["certificate-ttl"]; ttl != "" {
		cfg["certificate_ttl"] = ttl
	}
	return cfg, nil
}

// writeTbotConfig writes config as <new temp dir>/bot-config.yaml.
func writeTbotConfig(runnerTemp string, config map[string]any) (string, error) {
	data, err := yaml.Marshal(config)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(runnerTemp, "")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "bot-config.yaml")
	return path, os.WriteFile(path, data, 0o600)
}

// tbotEnv is the real action's baseEnvFromSharedInputs.
func tbotEnv(env []string, with map[string]string) []string {
	telemetry := "0"
	if stringToBool(with["anonymous-telemetry"]) {
		telemetry = "1"
	}
	out := slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		k, _, _ := strings.Cut(kv, "=")
		return k == "TELEPORT_ANONYMOUS_TELEMETRY" || k == "TELEPORT_PROXY" || k == "TELEPORT_AUTH_SERVER"
	})
	return append(out, "TELEPORT_ANONYMOUS_TELEMETRY="+telemetry)
}

// logIDTokenClaims fetches an ID token the way tbot will and logs its claims.
// It only warns on failure: tbot makes the same request and reports the real
// error.
func (authK8s) logIDTokenClaims(ctx context.Context, sc *StepContext) {
	jwt, err := fetchIDToken(ctx, sc.Env, tbotAudience)
	if err != nil {
		sc.Log("Warning: could not fetch the GitHub OIDC ID token to show its claims: " + err.Error())
		return
	}
	sc.Log("GitHub OIDC ID token claims:")
	sc.Log(describeIDToken(jwt)...)
}

func fetchIDToken(ctx context.Context, env []string, audience string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// The request URL already has a query string; tbot appends the audience.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, envLookup(env, "ACTIONS_ID_TOKEN_REQUEST_URL")+"&audience="+audience, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+envLookup(env, "ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var tok struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	if tok.Value == "" {
		return "", errors.New("response has no token value")
	}
	return tok.Value, nil
}

// describeIDToken decodes a JWT's payload (without verifying it) into sorted
// "  key: value" lines. It never returns the token itself; a token that
// can't be decoded yields a single explanatory line.
func describeIDToken(jwt string) []string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return []string{"  (not a JWT)"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return []string{"  (token payload is not base64url)"}
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return []string{"  (token payload is not a JSON object)"}
	}
	lines := make([]string, 0, len(claims))
	for _, k := range slices.Sorted(maps.Keys(claims)) {
		var v string
		switch c := claims[k].(type) {
		case string:
			v = c
		case json.Number:
			v = c.String()
		default:
			b, _ := json.Marshal(c)
			v = string(b)
		}
		lines = append(lines, "  "+k+": "+v)
	}
	return lines
}

// envLookup returns the value of name in env (KEY=value pairs).
func envLookup(env []string, name string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}
