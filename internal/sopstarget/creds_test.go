package sopstarget

import (
	"os"
	"strings"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/sopstarget/sopstest"
)

// docs/10 D6, G7: only a service account key, or a federation
// configuration whose subject token comes from a file, is a credential.
func TestValidateCredentials(t *testing.T) {
	wif := func(extra string) string {
		return `{"type":"external_account","audience":"//iam.googleapis.com/x","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"https://sts.googleapis.com/v1/token"` + extra + `}`
	}
	good := map[string]string{
		"a service account key":             `{"type":"service_account","client_email":"a@b","private_key":"k","token_uri":"https://oauth2.googleapis.com/token"}`,
		"federation from a file":            wif(`,"credential_source":{"file":"/var/run/secrets/tokens/gcp"}`),
		"federation with a format":          wif(`,"credential_source":{"file":"/t","format":{"type":"text"}}`),
		"federation with an impersonation":  wif(`,"credential_source":{"file":"/t"},"service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/x:generateAccessToken","service_account_impersonation":{"token_lifetime_seconds":600}`),
		"federation with a universe domain": wif(`,"credential_source":{"file":"/t"},"universe_domain":"googleapis.com","token_info_url":"https://sts.googleapis.com/v1/introspect"`),
	}
	for name, c := range good {
		if _, err := ValidateCredentials([]byte(c)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	sa := func(extra string) string {
		return `{"type":"service_account","client_email":"a@b","private_key":"k"` + extra + `}`
	}
	good["a key without a token_uri"] = sa(``)
	good["a key with a universe domain"] = sa(`,"universe_domain":"googleapis.com"`)
	wifAt := func(tokenURL, extra string) string {
		return `{"type":"external_account","audience":"//iam.googleapis.com/x","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"` + tokenURL + `","credential_source":{"file":"/t"}` + extra + `}`
	}
	// Where the token exchange is sent is the file's to say, and the
	// subject token goes with it: only Google's own are taken (M16).
	elsewhere := map[string]string{
		"a key's token_uri elsewhere":      sa(`,"token_uri":"https://evil.example/token"`),
		"a key's token_uri over http":      sa(`,"token_uri":"http://oauth2.googleapis.com/token"`),
		"a key's token_uri not a string":   sa(`,"token_uri":7`),
		"a key in another universe":        sa(`,"universe_domain":"evil.example"`),
		"an STS elsewhere":                 wifAt("https://evil.example/v1/token", ``),
		"an STS that only starts right":    wifAt("https://sts.googleapis.com.evil.example/v1/token", ``),
		"an STS with a user part":          wifAt("https://sts.googleapis.com@evil.example/v1/token", ``),
		"an STS over http":                 wifAt("http://sts.googleapis.com/v1/token", ``),
		"no STS":                           `{"type":"external_account","audience":"a","subject_token_type":"t","credential_source":{"file":"/t"}}`,
		"another universe":                 wifAt("https://sts.googleapis.com/v1/token", `,"universe_domain":"evil.example"`),
		"a token_info_url elsewhere":       wifAt("https://sts.googleapis.com/v1/token", `,"token_info_url":"https://evil.example/v1/introspect"`),
		"an impersonation elsewhere":       wifAt("https://sts.googleapis.com/v1/token", `,"service_account_impersonation_url":"https://evil.example/v1/projects/-/serviceAccounts/a@b:generateAccessToken"`),
		"an impersonation with a user":     wifAt("https://sts.googleapis.com/v1/token", `,"service_account_impersonation_url":"https://iamcredentials.googleapis.com@evil.example/v1/x:generateAccessToken"`),
		"an impersonation of another call": wifAt("https://sts.googleapis.com/v1/token", `,"service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/x:signBlob"`),
		"an impersonation with a query":    wifAt("https://sts.googleapis.com/v1/token", `,"service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/x:generateAccessToken?a=b"`),
	}
	for name, c := range elsewhere {
		if _, err := ValidateCredentials([]byte(c)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "evil") {
			t.Errorf("%s: the error holds the URL: %v", name, err)
		}
	}
	bad := map[string]string{
		"not JSON":                    `private-key-material`,
		"an array":                    `[]`,
		"no type":                     `{"client_email":"a@b"}`,
		"a user's refresh token":      `{"type":"authorized_user","refresh_token":"SECRET"}`,
		"an impersonated account":     `{"type":"impersonated_service_account","source_credentials":{}}`,
		"a workforce user":            `{"type":"external_account_authorized_user","refresh_token":"SECRET"}`,
		"a gdch account":              `{"type":"gdch_service_account"}`,
		"federation from a URL":       wif(`,"credential_source":{"url":"http://169.254.169.254/token"}`),
		"federation from a program":   wif(`,"credential_source":{"executable":{"command":"/bin/sh -c evil"}}`),
		"a file and a program":        wif(`,"credential_source":{"file":"/t","executable":{"command":"/bin/evil"}}`),
		"federation from AWS":         wif(`,"credential_source":{"environment_id":"aws1","regional_cred_verification_url":"https://sts"}`),
		"federation from a cert":      wif(`,"credential_source":{"certificate":{"use_default_certificate_config":true}}`),
		"federation without a source": wif(``),
		"an empty file source":        wif(`,"credential_source":{"file":""}`),
		"a workforce pool":            wif(`,"credential_source":{"file":"/t"},"workforce_pool_user_project":"p"`),
		"a client secret":             wif(`,"credential_source":{"file":"/t"},"client_id":"c","client_secret":"SECRET"`),
		"an unknown field":            wif(`,"credential_source":{"file":"/t"},"something_new":1`),
	}
	for name, c := range bad {
		_, err := ValidateCredentials([]byte(c))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// The error never holds what the file holds.
		for _, leak := range []string{"SECRET", "private-key-material", "/bin/", "169.254", "something_new", "client_secret", "environment_id", "workforce_pool"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error holds %q: %v", name, leak, err)
			}
		}
	}
	if _, err := ValidateCredentials([]byte(`{"type":"service_account","pad":"` + strings.Repeat("x", maxCredentialsFile) + `"}`)); err == nil {
		t.Error("a file over the size limit was accepted")
	}
}

// docs/10 D6: a federation configuration works end to end, the token is
// kept while the file stays the same, and a replaced file is used at
// once.
func TestFederationAndReload(t *testing.T) {
	f := sopstest.New(t)
	dir := t.TempDir()
	e := newEnvWith(t, f, f.ExternalAccountFile(t, dir))
	enc := encrypted(t, f)
	decrypt := append([]string{"decrypt"}, yamlFlags()...)
	if out, err := e.run(t, mustParse(t, enc, decrypt...)); err != nil || string(out) != secretYAML {
		t.Fatalf("a run with a federation configuration: %q %v", out, err)
	}
	if _, err := e.run(t, mustParse(t, enc, decrypt...)); err != nil {
		t.Fatal(err)
	}
	if n := f.TokenExchanges(); n != 1 {
		t.Fatalf("%d token exchanges for two runs on one file", n)
	}
	if errs := e.runner.CheckCredentials(); len(errs) != 0 {
		t.Fatalf("CheckCredentials: %v", errs)
	}
	if n := f.TokenExchanges(); n != 1 {
		t.Fatal("the startup check called Google")
	}

	// The Secret is replaced (docs/06 D4): the next run uses the new
	// file, with no restart.
	sa, err := os.ReadFile(f.ServiceAccountFile(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.creds, sa, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.run(t, mustParse(t, enc, decrypt...)); err != nil {
		t.Fatal(err)
	}
	if n := f.TokenExchanges(); n != 2 {
		t.Fatalf("%d token exchanges after the file changed", n)
	}

	// A broken file is reported by the startup check, by target, with
	// nothing from the file.
	if err := os.WriteFile(e.creds, []byte(`{"type":"authorized_user","refresh_token":"SECRET"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	errs := e.runner.CheckCredentials()
	if errs[testTarget] == nil || strings.Contains(errs[testTarget].Error(), "SECRET") {
		t.Fatalf("CheckCredentials on a broken file: %v", errs)
	}
}
