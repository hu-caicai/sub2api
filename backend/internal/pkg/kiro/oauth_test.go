//go:build unit

package kiro

import (
	"fmt"
	"testing"
	"time"
)

func TestBuildSocialSignInURLUsesAppPortal(t *testing.T) {
	got := BuildSocialSignInURL("http://localhost:49153", "challenge123", "state456")
	want := "https://app.kiro.dev/signin?code_challenge=challenge123&code_challenge_method=S256&redirect_from=KiroIDE&redirect_uri=http%3A%2F%2Flocalhost%3A49153&state=state456"
	if got != want {
		t.Fatalf("BuildSocialSignInURL() = %q, want %q", got, want)
	}
}

func TestBuildSocialTokenRedirectURI(t *testing.T) {
	got := BuildSocialTokenRedirectURI("http://localhost:49153", "/oauth/callback", "github")
	want := "http://localhost:49153/oauth/callback?login_option=github"
	if got != want {
		t.Fatalf("BuildSocialTokenRedirectURI() = %q, want %q", got, want)
	}
}

func TestSessionStoreGetDeletesExpiredSession(t *testing.T) {
	store := NewSessionStore()
	store.Set("expired", &AuthSession{CreatedAt: time.Now().Add(-2 * sessionTTL)})

	session, ok := store.Get("expired")
	if ok || session != nil {
		t.Fatalf("Get(expired) = (%v, %v), want (nil, false)", session, ok)
	}
	if _, exists := store.data["expired"]; exists {
		t.Fatalf("expired session should be deleted from the store")
	}
}

func TestSessionStoreSetPrunesExpiredSessions(t *testing.T) {
	store := NewSessionStore()
	now := time.Now()
	for i := 0; i < sessionCleanupMin; i++ {
		store.data[fmt.Sprintf("expired-%d", i)] = &AuthSession{CreatedAt: now.Add(-2 * sessionTTL)}
	}
	store.setCount = sessionCleanupEvery - 1

	store.Set("fresh", &AuthSession{CreatedAt: now})

	if len(store.data) != 1 {
		t.Fatalf("store size = %d, want 1", len(store.data))
	}
	if _, ok := store.data["fresh"]; !ok {
		t.Fatalf("fresh session should remain after pruning")
	}
}

func TestParseImportedTokenInfersIDCAuthMetadataFromClientCredentials(t *testing.T) {
	token, err := ParseImportedToken(`{
		"accessToken": "access-token",
		"refreshToken": "refresh-token",
		"provider": "Google",
		"clientId": "client-id",
		"clientSecret": "client-secret"
	}`, "", ProviderBuilderId)
	if err != nil {
		t.Fatalf("ParseImportedToken() error = %v", err)
	}

	if token.AuthMethod != "idc" {
		t.Fatalf("AuthMethod = %q, want idc", token.AuthMethod)
	}
	if token.Provider != ProviderBuilderId {
		t.Fatalf("Provider = %q, want %q", token.Provider, ProviderBuilderId)
	}
	if token.Region != defaultIDCRegion {
		t.Fatalf("Region = %q, want %q", token.Region, defaultIDCRegion)
	}
}

func TestParseImportedTokenInfersIDCAuthMetadataFromDeviceRegistration(t *testing.T) {
	token, err := ParseImportedToken(`{
		"accessToken": "access-token",
		"refreshToken": "refresh-token",
		"provider": "Google",
		"clientIdHash": "client-id-hash"
	}`, `{
		"clientId": "client-id",
		"clientSecret": "client-secret"
	}`, ProviderEnterprise)
	if err != nil {
		t.Fatalf("ParseImportedToken() error = %v", err)
	}

	if token.ClientID != "client-id" {
		t.Fatalf("ClientID = %q, want client-id", token.ClientID)
	}
	if token.ClientSecret != "client-secret" {
		t.Fatalf("ClientSecret = %q, want client-secret", token.ClientSecret)
	}
	if token.AuthMethod != "idc" {
		t.Fatalf("AuthMethod = %q, want idc", token.AuthMethod)
	}
	if token.Provider != ProviderEnterprise {
		t.Fatalf("Provider = %q, want %q", token.Provider, ProviderEnterprise)
	}
}

func TestParseImportedTokenDefaultsProviderToGoogle(t *testing.T) {
	token, err := ParseImportedToken(`{
		"accessToken": "access-token",
		"refreshToken": "refresh-token",
		"authMethod": "social",
		"provider": "AWS"
	}`, "", "")
	if err != nil {
		t.Fatalf("ParseImportedToken() error = %v", err)
	}
	if token.Provider != ProviderGoogle {
		t.Fatalf("Provider = %q, want %q", token.Provider, ProviderGoogle)
	}
}

func TestParseImportedTokenUsesRequestedProvider(t *testing.T) {
	token, err := ParseImportedToken(`{
		"accessToken": "access-token",
		"refreshToken": "refresh-token",
		"authMethod": "social",
		"provider": "Google"
	}`, "", "  Github  ")
	if err != nil {
		t.Fatalf("ParseImportedToken() error = %v", err)
	}
	if token.Provider != ProviderGithub {
		t.Fatalf("Provider = %q, want %q", token.Provider, ProviderGithub)
	}
}

func TestParseImportedTokenRejectsInvalidRequestedProvider(t *testing.T) {
	if _, err := ParseImportedToken(`{
		"accessToken": "access-token",
		"authMethod": "social",
		"provider": "Google"
	}`, "", "Gitlab"); err == nil {
		t.Fatal("ParseImportedToken() expected error for invalid requested provider, got nil")
	}
}

func TestParseImportedTokenAcceptsWhitelistedProviders(t *testing.T) {
	for _, provider := range []string{ProviderGoogle, ProviderGithub} {
		token, err := ParseImportedToken(`{
			"accessToken": "access-token",
			"refreshToken": "refresh-token",
			"authMethod": "social"
		}`, "", provider)
		if err != nil {
			t.Fatalf("ParseImportedToken(%s) error = %v", provider, err)
		}
		if token.Provider != provider {
			t.Fatalf("Provider = %q, want %q", token.Provider, provider)
		}
	}
}

func TestParseImportedTokenNormalizesExpiresAt(t *testing.T) {
	cases := []struct {
		name      string
		expiresAt string
	}{
		{"utc with millis", "2026-06-29T09:33:49.114Z"},
		{"utc no millis", "2026-06-29T09:33:49Z"},
		{"naive treated as utc", "2026-09-27T08:46:31.070"},
		{"with offset", "2026-06-29T16:56:19+08:00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := ParseImportedToken(`{
				"accessToken": "access-token",
				"authMethod": "social",
				"expiresAt": "`+tc.expiresAt+`"
			}`, "", ProviderGoogle)
			if err != nil {
				t.Fatalf("ParseImportedToken() error = %v", err)
			}
			// 归一化后必须能被 RFC3339 解析,且为本地时区表示。
			parsed, perr := time.Parse(time.RFC3339, token.ExpiresAt)
			if perr != nil {
				t.Fatalf("ExpiresAt %q not RFC3339: %v", token.ExpiresAt, perr)
			}
			if token.ExpiresAt != parsed.Local().Format(time.RFC3339) {
				t.Fatalf("ExpiresAt = %q, want local RFC3339", token.ExpiresAt)
			}
		})
	}
}

func TestParseImportedTokenRejectsInvalidExpiresAt(t *testing.T) {
	if _, err := ParseImportedToken(`{
		"accessToken": "access-token",
		"authMethod": "social",
		"expiresAt": "not-a-time"
	}`, "", ProviderGoogle); err == nil {
		t.Fatalf("ParseImportedToken() expected error for invalid expiresAt, got nil")
	}
}

func TestResolveIDCProvider(t *testing.T) {
	if got := resolveIDCProvider(BuilderIDStartURL); got != ProviderBuilderId {
		t.Fatalf("resolveIDCProvider(builder) = %q, want %q", got, ProviderBuilderId)
	}
	if got := resolveIDCProvider(""); got != ProviderBuilderId {
		t.Fatalf("resolveIDCProvider(empty) = %q, want %q", got, ProviderBuilderId)
	}
	if got := resolveIDCProvider("https://d-9066029b12.awsapps.com/start/"); got != ProviderEnterprise {
		t.Fatalf("resolveIDCProvider(custom) = %q, want %q", got, ProviderEnterprise)
	}
}
