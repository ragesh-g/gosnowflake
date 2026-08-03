package gosnowflake

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	sfconfig "github.com/snowflakedb/gosnowflake/v2/internal/config"
)

func TestGetTokenFromResponseFail(t *testing.T) {
	response := "GET /?fakeToken=fakeEncodedSamlToken HTTP/1.1\r\n" +
		"Host: localhost:54001\r\n" +
		"Connection: keep-alive\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n" +
		"User-Agent: userAgentStr\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n" +
		"Referer: https://myaccount.snowflakecomputing.com/fed/login\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n\r\n"

	_, err := getTokenFromResponse(response)
	if err == nil {
		t.Errorf("Should have failed parsing the malformed response.")
	}
}

func TestGetTokenFromResponse(t *testing.T) {
	response := "GET /?token=GETtokenFromResponse HTTP/1.1\r\n" +
		"Host: localhost:54001\r\n" +
		"Connection: keep-alive\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n" +
		"User-Agent: userAgentStr\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n" +
		"Referer: https://myaccount.snowflakecomputing.com/fed/login\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n\r\n"

	expected := "GETtokenFromResponse"

	token, err := getTokenFromResponse(response)
	if err != nil {
		t.Errorf("Failed to get the token. Err: %#v", err)
	}
	if token != expected {
		t.Errorf("Expected: %s, found: %s", expected, token)
	}
}

func TestBuildResponse(t *testing.T) {
	resp, err := buildResponse(fmt.Sprintf(samlSuccessHTML, "Go"))
	assertNilF(t, err)
	bytes := resp.Bytes()
	respStr := string(bytes[:])
	if !strings.Contains(respStr, "Your identity was confirmed and propagated to Snowflake Go.\nYou can close this window now and go back where you started from.") {
		t.Fatalf("failed to build response")
	}
}

type acceptNotifyingListener struct {
	net.Listener
	accepted chan<- struct{}
}

func (l acceptNotifyingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		select {
		case l.accepted <- struct{}{}:
		default:
		}
	}
	return conn, err
}

func TestWaitForSamlResponseAcceptsCallbackAfterIdleConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assertNilF(t, err)
	accepted := make(chan struct{}, 1)
	notifyingListener := acceptNotifyingListener{Listener: listener, accepted: accepted}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		token string
		err   error
	}
	resultChan := make(chan result, 1)
	go func() {
		token, err := waitForSamlResponse(ctx, notifyingListener, "Go")
		resultChan <- result{token: token, err: err}
	}()

	idleConn, err := net.Dial("tcp", listener.Addr().String())
	assertNilF(t, err)
	defer idleConn.Close()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("idle connection was not accepted")
	}

	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/?token=test%2Btoken")
	assertNilF(t, err)
	defer response.Body.Close()
	assertEqualE(t, response.StatusCode, http.StatusOK)

	select {
	case got := <-resultChan:
		assertNilF(t, got.err)
		assertEqualE(t, got.token, "test%2Btoken")
	case <-ctx.Done():
		t.Fatal("real callback was blocked by the idle connection")
	}
}

func TestWaitForSamlResponseStopsOnContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assertNilF(t, err)
	accepted := make(chan struct{}, 1)
	notifyingListener := acceptNotifyingListener{Listener: listener, accepted: accepted}

	ctx, cancel := context.WithCancel(context.Background())
	resultChan := make(chan error, 1)
	go func() {
		_, err := waitForSamlResponse(ctx, notifyingListener, "Go")
		resultChan <- err
	}()

	idleConn, err := net.Dial("tcp", listener.Addr().String())
	assertNilF(t, err)
	defer idleConn.Close()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("idle connection was not accepted")
	}

	cancel()
	select {
	case err := <-resultChan:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not stop after context cancellation")
	}
}

func postAuthExternalBrowserError(_ context.Context, _ *snowflakeRestful, _ map[string]string, _ []byte, _ time.Duration) (*authResponse, error) {
	return &authResponse{}, errors.New("failed to get SAML response")
}

func postAuthExternalBrowserErrorDelayed(_ context.Context, _ *snowflakeRestful, _ map[string]string, _ []byte, _ time.Duration) (*authResponse, error) {
	time.Sleep(2 * time.Second)
	return &authResponse{}, errors.New("failed to get SAML response")
}

func postAuthExternalBrowserFail(_ context.Context, _ *snowflakeRestful, _ map[string]string, _ []byte, _ time.Duration) (*authResponse, error) {
	return &authResponse{
		Success: false,
		Message: "external browser auth failed",
	}, nil
}

func postAuthExternalBrowserFailWithCode(_ context.Context, _ *snowflakeRestful, _ map[string]string, _ []byte, _ time.Duration) (*authResponse, error) {
	return &authResponse{
		Success: false,
		Message: "failed to connect to db",
		Code:    "260008",
	}, nil
}

func TestUnitAuthenticateByExternalBrowser(t *testing.T) {
	authenticator := "externalbrowser"
	application := "testapp"
	account := "testaccount"
	user := "u"
	timeout := sfconfig.DefaultExternalBrowserTimeout
	sr := &snowflakeRestful{
		Protocol:         "https",
		Host:             "abc.com",
		Port:             443,
		FuncPostAuthSAML: postAuthExternalBrowserError,
		TokenAccessor:    getSimpleTokenAccessor(),
	}
	_, _, err := authenticateByExternalBrowser(context.Background(), sr, authenticator, application, account, user, timeout, ConfigBoolTrue)
	if err == nil {
		t.Fatal("should have failed.")
	}
	sr.FuncPostAuthSAML = postAuthExternalBrowserFail
	_, _, err = authenticateByExternalBrowser(context.Background(), sr, authenticator, application, account, user, timeout, ConfigBoolTrue)
	if err == nil {
		t.Fatal("should have failed.")
	}
	sr.FuncPostAuthSAML = postAuthExternalBrowserFailWithCode
	_, _, err = authenticateByExternalBrowser(context.Background(), sr, authenticator, application, account, user, timeout, ConfigBoolTrue)
	if err == nil {
		t.Fatal("should have failed.")
	}
	driverErr, ok := err.(*SnowflakeError)
	if !ok {
		t.Fatalf("should be snowflake error. err: %v", err)
	}
	if driverErr.Number != ErrCodeFailedToConnect {
		t.Fatalf("unexpected error code. expected: %v, got: %v", ErrCodeFailedToConnect, driverErr.Number)
	}
}

func TestAuthenticationTimeout(t *testing.T) {
	authenticator := "externalbrowser"
	application := "testapp"
	account := "testaccount"
	user := "u"
	timeout := 1 * time.Second
	sr := &snowflakeRestful{
		Protocol:         "https",
		Host:             "abc.com",
		Port:             443,
		FuncPostAuthSAML: postAuthExternalBrowserErrorDelayed,
		TokenAccessor:    getSimpleTokenAccessor(),
	}
	_, _, err := authenticateByExternalBrowser(context.Background(), sr, authenticator, application, account, user, timeout, ConfigBoolTrue)
	assertEqualE(t, err.Error(), "authentication timed out", err.Error())
}

func TestExternalBrowserAuthContextError(t *testing.T) {
	timeoutCtx, cancelTimeout := context.WithTimeoutCause(context.Background(), 0, errExternalBrowserAuthTimeout)
	defer cancelTimeout()
	<-timeoutCtx.Done()
	if !errors.Is(externalBrowserAuthContextError(timeoutCtx), errExternalBrowserAuthTimeout) {
		t.Fatal("external-browser timeout cause was not preserved")
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(externalBrowserAuthContextError(canceledCtx), context.Canceled) {
		t.Fatal("caller cancellation was not preserved")
	}
}

func Test_createLocalTCPListener(t *testing.T) {
	listener, err := createLocalTCPListener(0)
	if err != nil {
		t.Fatalf("createLocalTCPListener() failed: %v", err)
	}
	if listener == nil {
		t.Fatal("createLocalTCPListener() returned nil listener")
	}

	// Close the listener after the test.
	defer listener.Close()
}

func TestConfiguredExternalBrowserCallbackPort(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   string
		want    int
		wantErr bool
	}{
		{name: "unset uses an ephemeral port"},
		{name: "zero uses an ephemeral port", value: "0"},
		{name: "pinned port", value: "3037", want: 3037},
		{name: "negative port", value: "-1", wantErr: true},
		{name: "port too large", value: "65536", wantErr: true},
		{name: "non-numeric port", value: "not-a-port", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(externalBrowserCallbackPortEnv, test.value)
			got, err := configuredExternalBrowserCallbackPort()
			if test.wantErr {
				assertNotNilF(t, err)
				return
			}
			assertNilF(t, err)
			assertEqualE(t, got, test.want)
		})
	}
}

func TestUnitGetLoginURL(t *testing.T) {
	expectedScheme := "https"
	expectedHost := "abc.com:443"
	user := "u"
	callbackPort := 123
	sr := &snowflakeRestful{
		Protocol:      "https",
		Host:          "abc.com",
		Port:          443,
		TokenAccessor: getSimpleTokenAccessor(),
	}

	loginURL, proofKey, err := getLoginURL(sr, user, callbackPort)
	assertNilF(t, err, "failed to get login URL")
	assertNotNilF(t, len(proofKey), "proofKey should be non-empty string")

	urlPtr, err := url.Parse(loginURL)
	assertNilF(t, err, "failed to parse the login URL")
	assertEqualF(t, urlPtr.Scheme, expectedScheme)
	assertEqualF(t, urlPtr.Host, expectedHost)
	assertEqualF(t, urlPtr.Path, consoleLoginRequestPath)
	assertStringContainsF(t, urlPtr.RawQuery, "login_name")
	assertStringContainsF(t, urlPtr.RawQuery, "browser_mode_redirect_port")
	assertStringContainsF(t, urlPtr.RawQuery, "proof_key")
}

type nonInteractiveSamlResponseProvider struct {
	t *testing.T
}

func (provider *nonInteractiveSamlResponseProvider) run(url string) error {
	go func() {
		resp, err := http.Get(url)
		assertNilF(provider.t, err)
		assertEqualE(provider.t, resp.StatusCode, http.StatusOK)
	}()
	return nil
}
