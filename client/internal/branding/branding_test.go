package branding

import "testing"

func TestResolveDerivesWhiteLabelNamespaces(t *testing.T) {
	t.Parallel()
	config, err := Resolve(Config{Name: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if config.DisplayName != "ACME CLI Gateway client" ||
		config.EnvPrefix != "ACME" ||
		config.ConfigDirName != "acme" ||
		config.CacheDirName != "acme" ||
		config.KeyringService != "acme-cli-refresh-token" ||
		config.UserAgent != "acme-cli" {
		t.Fatalf("resolved config = %#v", config)
	}
	if got := config.Env("TOKEN"); got != "ACME_TOKEN" {
		t.Fatalf("token environment name = %q", got)
	}
}

func TestResolveRejectsUnsafeBuildValues(t *testing.T) {
	t.Parallel()
	tests := []Config{
		{Name: "../acme"},
		{Name: "acme", EnvPrefix: "ACME-NAME"},
		{Name: "acme", ConfigDirName: "../shared"},
		{Name: "acme", UserAgent: "acme cli"},
		{Name: "acme", DisplayName: "ACME\nCLI"},
	}
	for _, test := range tests {
		if _, err := Resolve(test); err == nil {
			t.Errorf("Resolve(%#v) succeeded", test)
		}
	}
}
