package https

import (
	"testing"
)

func TestXFCCParser(t *testing.T) {
	testVector := `By=http://frontend.lyft.com;Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;Subject="/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client";URI=http://testclient.lyft.com`
	testCases := []struct {
		Field string
		Value string
	}{
		{
			Field: "By",
			Value: "http://frontend.lyft.com",
		},
		{
			Field: "Hash",
			Value: "468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688",
		},
		{
			Field: "Subject",
			Value: "/C=US/ST=CA/L=San Francisco/OU=Lyft/CN=Test Client",
		},
		{
			Field: "URI",
			Value: "http://testclient.lyft.com",
		},
	}
	for _, tc := range testCases {
		if value := extractField(tc.Field, testVector); value != tc.Value {
			t.Errorf("unexpected field %s value: %s != %s", tc.Field, value, tc.Value)
		}
	}
	if value := extractField("Cert", testVector); value != "" {
		t.Errorf("expect empty value for no field found: %s", value)
	}
	if value := extractField("Cert", testVector+`;Key="\`); value != "" {
		t.Errorf("expect empty value for no field and invalid string: %s", value)
	}
	if value := extractField("Cert", ""); value != "" {
		t.Errorf("expect empty value for empty header: %s", value)
	}
}
