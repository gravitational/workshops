package aws

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// dockerClient is the little of the Docker Engine API the simulator needs to
// play the instances' SSM agent and IMDS: inspect a container, and exec a
// command in it.
type dockerClient struct {
	http *http.Client // nil: no Docker socket, so no instance is Online

	mu    sync.Mutex
	cache map[string]containerInfo
}

type containerInfo struct {
	fetched time.Time
	running bool
	ips     []string
}

func newDockerClient(socket string) *dockerClient {
	d := &dockerClient{cache: map[string]containerInfo{}}
	if socket == "" {
		return d
	}
	d.http = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	return d
}

func (d *dockerClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	if d.http == nil {
		return nil, fmt.Errorf("no Docker socket configured (AWS_DOCKER_SOCKET)")
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("docker %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

// inspect returns a container's state, cached for a few seconds (IMDS looks
// up callers by IP on every request).
func (d *dockerClient) inspect(name string) containerInfo {
	d.mu.Lock()
	c, ok := d.cache[name]
	d.mu.Unlock()
	if ok && time.Since(c.fetched) < 5*time.Second {
		return c
	}
	c = containerInfo{fetched: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if resp, err := d.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil); err == nil {
		var v struct {
			State           struct{ Running bool }
			NetworkSettings struct {
				Networks map[string]struct{ IPAddress string }
			}
		}
		json.NewDecoder(resp.Body).Decode(&v)
		resp.Body.Close()
		c.running = v.State.Running
		for _, n := range v.NetworkSettings.Networks {
			if n.IPAddress != "" {
				c.ips = append(c.ips, n.IPAddress)
			}
		}
	}
	d.mu.Lock()
	d.cache[name] = c
	d.mu.Unlock()
	return c
}

func (d *dockerClient) running(name string) bool { return d.inspect(name).running }

// execResult is a finished command.
type execResult struct {
	exitCode       int
	stdout, stderr string
}

// exec runs cmd in the container as root and waits for it to finish.
func (d *dockerClient) exec(ctx context.Context, container string, cmd []string) (execResult, error) {
	resp, err := d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(container)+"/exec", map[string]any{
		"Cmd": cmd, "AttachStdout": true, "AttachStderr": true, "User": "root",
	})
	if err != nil {
		return execResult{}, err
	}
	var created struct{ Id string }
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	resp, err = d.do(ctx, http.MethodPost, "/exec/"+created.Id+"/start", map[string]any{"Detach": false, "Tty": false})
	if err != nil {
		return execResult{}, err
	}
	var stdout, stderr bytes.Buffer
	err = demux(resp.Body, &stdout, &stderr)
	resp.Body.Close()
	if err != nil {
		return execResult{}, err
	}

	resp, err = d.do(ctx, http.MethodGet, "/exec/"+created.Id+"/json", nil)
	if err != nil {
		return execResult{}, err
	}
	var inspect struct{ ExitCode int }
	json.NewDecoder(resp.Body).Decode(&inspect)
	resp.Body.Close()
	return execResult{inspect.ExitCode, stdout.String(), stderr.String()}, nil
}

// demux splits Docker's multiplexed attach stream: frames of an 8-byte header
// (stream type, 3 zero bytes, big-endian length) and a payload.
func demux(r io.Reader, stdout, stderr io.Writer) error {
	br := bufio.NewReader(r)
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		w := stdout
		if hdr[0] == 2 {
			w = stderr
		}
		if _, err := io.CopyN(w, br, int64(binary.BigEndian.Uint32(hdr[4:]))); err != nil {
			return err
		}
	}
}
