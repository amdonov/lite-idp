package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func emptyRun(*cobra.Command, []string) {}

func executeCommand(root *cobra.Command, args ...string) (output string, err error) {
	buf := new(bytes.Buffer)
	out = buf // overrides writer from serviceProvider.go
	root.SetOutput(buf)
	root.SetArgs(args)
	_, err = root.ExecuteC()
	return buf.String(), err
}

func checkStringContains(t *testing.T, got, expected string) {
	if !strings.Contains(got, expected) {
		t.Errorf("Expected to contain: \n %v\nGot:\n %v\n", expected, got)
	}
}

func addServiceProvider(metadata string) (output string, err error) {
	// set a dummy config file for the command to write to
	viper.SetConfigFile("config.yaml")

	rootCmd := &cobra.Command{Use: "add", Args: cobra.NoArgs, Run: emptyRun}
	rootCmd.AddCommand(serviceProviderCmd)
	return executeCommand(rootCmd, "service-provider", metadata)
}

func TestAddServiceProviderCommand(t *testing.T) {
	output, err := addServiceProvider("../idp/testdata/sp-metadata.xml")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	checkStringContains(t, output, "Successfully added service provider from metadata ../idp/testdata/sp-metadata.xml")
}

func TestAddServiceProviderCommandWrongFile(t *testing.T) {
	_, err := addServiceProvider("dontexist.xml")
	if err == nil {
		t.Error("Expected 'no such file or directory' error")
	} else {
		checkStringContains(t, err.Error(), "open dontexist.xml: no such file or directory")
	}
}
