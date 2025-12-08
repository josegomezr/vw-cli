package main_test

import (
	"flag"
	vwcli "github.com/josegomezr/vw-cli/cmd/vw-cli"
	"os"
	"testing"
)

func TestArgParseNoArgs(t *testing.T) {
	vwcli.FlagMode = flag.ContinueOnError
	args := []string{}
	opts, err := vwcli.ParseArgs(args)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	if cmd := opts.Command; cmd != "help" {
		t.Fatalf("Unexpected command: %s", cmd)
	}
}

func TestArgParseSetConfigDir(t *testing.T) {
	vwcli.FlagMode = flag.ContinueOnError
	tmpdir := os.TempDir()
	args := []string{"--config-dir", tmpdir}

	opts, err := vwcli.ParseArgs(args)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if cmd := opts.Command; cmd != "help" {
		t.Fatalf("Unexpected command: %s", cmd)
	}
	if cfgdir := opts.ConfigDir; cfgdir != tmpdir {
		t.Fatalf("Unexpected command: %s", cfgdir)
	}
}

func TestArgParseHelp(t *testing.T) {
	vwcli.FlagMode = flag.ContinueOnError
	t.Run("When using the word help", func(t *testing.T) {
		args := []string{"help"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "help" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
	})

	t.Run("When using the flag: -h", func(t *testing.T) {
		args := []string{"-h"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "help" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
	})

	t.Run("When using the flag: --help", func(t *testing.T) {
		args := []string{"--help"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "help" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
	})
}

func TestArgParseLogout(t *testing.T) {
	vwcli.FlagMode = flag.ContinueOnError
	args := []string{"logout"}
	opts, err := vwcli.ParseArgs(args)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if cmd := opts.Command; cmd != "logout" {
		t.Fatalf("Unexpected command: %s", cmd)
	}
}

func TestArgParseShow(t *testing.T) {
	vwcli.FlagMode = flag.ContinueOnError
	t.Run("without arguments", func(t *testing.T) {
		args := []string{"show"}
		_, err := vwcli.ParseArgs(args)
		if err == nil {
			t.Fatalf("Unexpected success: %s", err)
		}
	})

	t.Run("with secret name", func(t *testing.T) {
		args := []string{"show", "my-secret"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "show" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
		if cipher := opts.ShowOpts.Cipher; cipher != "my-secret" {
			t.Fatalf("Unexpected cipher: %s", cipher)
		}
	})

	t.Run("with secret name + folder id", func(t *testing.T) {
		args := []string{"show", "--folder", "bar", "my-secret"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "show" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
		if folder := opts.ShowOpts.Folder; folder != "bar" {
			t.Fatalf("Unexpected folder: %s", folder)
		}
	})

	t.Run("with secret name + organization id", func(t *testing.T) {
		args := []string{"show", "--organization", "foo", "my-secret"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "show" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
		if organization := opts.ShowOpts.Organization; organization != "foo" {
			t.Fatalf("Unexpected organization: %s", organization)
		}
	})
}


func TestArgParseList(t *testing.T) {
	vwcli.FlagMode = flag.ContinueOnError
	t.Run("When using the shortcut: ls", func(t *testing.T) {
		args := []string{"ls"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "list" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
	})
	t.Run("When using the word: list", func(t *testing.T) {
		args := []string{"list"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "list" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
	})

	t.Run("with --folder", func(t *testing.T) {
		args := []string{"list", "--folder", "bar", "my-secret"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "list" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
		if folder := opts.ListOpts.Folder; folder != "bar" {
			t.Fatalf("Unexpected folder: %s", folder)
		}
	})

	t.Run("with --organization", func(t *testing.T) {
		args := []string{"list", "--organization", "foo", "my-secret"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "list" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
		if organization := opts.ListOpts.Organization; organization != "foo" {
			t.Fatalf("Unexpected organization: %s", organization)
		}
	})
}

func TestArgParseLogin(t *testing.T) {
	vwcli.FlagMode = flag.ContinueOnError
	t.Run("Without flags", func(t *testing.T) {
		args := []string{"login"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "login" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
	})

	t.Run("With -h", func(t *testing.T) {
		args := []string{"login", "-h"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "login" {
			t.Fatalf("Unexpected command: %s", cmd)
		}
	})

	t.Run("With api-key: --api-key", func(t *testing.T) {
		args := []string{"login", "--api-key", "foo.bar"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "login" {
			t.Fatalf("Unexpected command: %s", cmd)
		}

		if apikey := opts.LoginOpts.APIKey; apikey != "foo.bar" {
			t.Fatalf("api key does not match: %s", apikey)
		}
	})

	t.Run("With api-key: --email", func(t *testing.T) {
		args := []string{"login", "--email", "foo@bar.baz"}
		opts, err := vwcli.ParseArgs(args)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "login" {
			t.Fatalf("Unexpected command: %s", cmd)
		}

		if email := opts.LoginOpts.Email; email != "foo@bar.baz" {
			t.Fatalf("api key does not match: %s", email)
		}
	})

	t.Run("With api-key: --master-password-file", func(t *testing.T) {
		f, err := os.CreateTemp(os.TempDir(), "example")
		if err != nil {
			t.Fatalf("error: %s", err)
		}
		defer os.Remove(f.Name()) // clean up
		f.Write([]byte("what-a-password"))

		args := []string{"login", "--master-password-file", f.Name()}
		opts, err := vwcli.ParseArgs(args)

		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		if cmd := opts.Command; cmd != "login" {
			t.Fatalf("Unexpected command: %s", cmd)
		}

		if email := opts.LoginOpts.MasterPassword; email != "what-a-password" {
			t.Fatalf("api key does not match: %s", email)
		}
	})
}
