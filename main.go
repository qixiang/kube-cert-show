package main

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"gopkg.in/yaml.v3"
)

// Common OID to short name mappings (RFC 4519, X.520)
var oidNames = map[string]string{
	"2.5.4.3":                     "CN",
	"2.5.4.4":                     "SN",
	"2.5.4.5":                     "serialNumber",
	"2.5.4.6":                     "C",
	"2.5.4.7":                     "L",
	"2.5.4.8":                     "ST",
	"2.5.4.9":                     "street",
	"2.5.4.10":                    "O",
	"2.5.4.11":                    "OU",
	"2.5.4.12":                    "title",
	"2.5.4.17":                    "postalCode",
	"2.5.4.42":                    "GN",
	"2.5.4.65":                    "pseudonym",
	"1.2.840.113549.1.9.1":        "emailAddress",
	"0.9.2342.19200300.100.1.25":  "DC",
	"0.9.2342.19200300.100.1.1":   "UID",
}

func oidToShortName(oid asn1.ObjectIdentifier) string {
	if name, ok := oidNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

// formatDN formats a pkix.Name in OpenSSL style: "C = US, O = Example, CN = CA"
func formatDN(name pkix.Name) string {
	var parts []string
	for _, atv := range name.Names {
		parts = append(parts, oidToShortName(atv.Type)+" = "+fmt.Sprintf("%v", atv.Value))
	}
	return strings.Join(parts, ", ")
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, byt := range b {
		parts[i] = fmt.Sprintf("%02X", byt)
	}
	return strings.Join(parts, ":")
}

func colonHexLower(b []byte) string {
	parts := make([]string, len(b))
	for i, byt := range b {
		parts[i] = fmt.Sprintf("%02x", byt)
	}
	return strings.Join(parts, ":")
}

func serialHex(s *big.Int) string {
	b := s.Bytes()
	if len(b) == 0 {
		return "00"
	}
	return colonHexLower(b)
}

func sha1Fingerprint(der []byte) string {
	h := sha1.Sum(der)
	return colonHex(h[:])
}

// opensslTime formats a time in OpenSSL's style: "Jan  2 15:04:05 2006 GMT"
// The _2 format specifier space-pads single-digit days, matching OpenSSL output.
func opensslTime(t time.Time) string {
	return t.UTC().Format("Jan _2 15:04:05 2006 GMT")
}

var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Non Repudiation"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

func formatKeyUsage(ku x509.KeyUsage) string {
	var names []string
	for _, kn := range keyUsageBits {
		if ku&kn.bit != 0 {
			names = append(names, kn.name)
		}
	}
	return strings.Join(names, ", ")
}

var ekuNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth:                 "TLS Web Client Authentication",
	x509.ExtKeyUsageCodeSigning:                "Code Signing",
	x509.ExtKeyUsageEmailProtection:            "E-mail Protection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSec End System",
	x509.ExtKeyUsageIPSECTunnel:                "IPSec Tunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSec User",
	x509.ExtKeyUsageTimeStamping:               "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape Server Gated Crypto",
}

func isCriticalExt(cert *x509.Certificate, oidStr string) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == oidStr && ext.Critical {
			return true
		}
	}
	return false
}

func printCertFull(idx int, dataKey string, cert *x509.Certificate, der []byte) {
	header := fmt.Sprintf("Certificate [%d]  (key: %s)", idx, dataKey)
	fmt.Println(header)
	fmt.Println(strings.Repeat("─", len(header)))

	serialBytes := cert.SerialNumber.Bytes()
	if len(serialBytes) == 0 {
		serialBytes = []byte{0}
	}

	fmt.Printf("    Data:\n")
	fmt.Printf("        Version: %d (0x%x)\n", cert.Version, cert.Version-1)
	fmt.Printf("        Serial Number:\n")
	fmt.Printf("            %s\n", colonHexLower(serialBytes))
	fmt.Printf("        Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("        Issuer: %s\n", formatDN(cert.Issuer))
	fmt.Printf("        Validity\n")
	fmt.Printf("            Not Before: %s\n", opensslTime(cert.NotBefore))
	fmt.Printf("            Not After : %s\n", opensslTime(cert.NotAfter))
	fmt.Printf("        Subject: %s\n", formatDN(cert.Subject))
	fmt.Printf("        Subject Public Key Info:\n")
	fmt.Printf("            Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)

	fmt.Printf("        X509v3 extensions:\n")

	// Key Usage (OID 2.5.29.15)
	if cert.KeyUsage != 0 {
		critStr := ""
		if isCriticalExt(cert, "2.5.29.15") {
			critStr = " critical"
		}
		fmt.Printf("            X509v3 Key Usage:%s\n", critStr)
		fmt.Printf("                %s\n", formatKeyUsage(cert.KeyUsage))
	}

	// Extended Key Usage (OID 2.5.29.37)
	if len(cert.ExtKeyUsage) > 0 {
		critStr := ""
		if isCriticalExt(cert, "2.5.29.37") {
			critStr = " critical"
		}
		fmt.Printf("            X509v3 Extended Key Usage:%s\n", critStr)
		var names []string
		for _, eku := range cert.ExtKeyUsage {
			if name, ok := ekuNames[eku]; ok {
				names = append(names, name)
			}
		}
		fmt.Printf("                %s\n", strings.Join(names, ", "))
	}

	// Basic Constraints (OID 2.5.29.19)
	if cert.BasicConstraintsValid {
		critStr := ""
		if isCriticalExt(cert, "2.5.29.19") {
			critStr = " critical"
		}
		fmt.Printf("            X509v3 Basic Constraints:%s\n", critStr)
		if cert.IsCA {
			if cert.MaxPathLen > 0 {
				fmt.Printf("                CA:TRUE, pathlen:%d\n", cert.MaxPathLen)
			} else if cert.MaxPathLenZero {
				fmt.Printf("                CA:TRUE, pathlen:0\n")
			} else {
				fmt.Printf("                CA:TRUE\n")
			}
		} else {
			fmt.Printf("                CA:FALSE\n")
		}
	}

	// Subject Key Identifier (OID 2.5.29.14)
	if len(cert.SubjectKeyId) > 0 {
		fmt.Printf("            X509v3 Subject Key Identifier:\n")
		fmt.Printf("                %s\n", colonHex(cert.SubjectKeyId))
	}

	// Authority Key Identifier (OID 2.5.29.35)
	if len(cert.AuthorityKeyId) > 0 {
		fmt.Printf("            X509v3 Authority Key Identifier:\n")
		fmt.Printf("                keyid:%s\n", colonHex(cert.AuthorityKeyId))
	}

	// Subject Alternative Names (OID 2.5.29.17)
	if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs) > 0 {
		critStr := ""
		if isCriticalExt(cert, "2.5.29.17") {
			critStr = " critical"
		}
		fmt.Printf("            X509v3 Subject Alternative Name:%s\n", critStr)
		var sans []string
		for _, dns := range cert.DNSNames {
			sans = append(sans, "DNS:"+dns)
		}
		for _, ip := range cert.IPAddresses {
			sans = append(sans, "IP Address:"+ip.String())
		}
		for _, email := range cert.EmailAddresses {
			sans = append(sans, "email:"+email)
		}
		for _, uri := range cert.URIs {
			sans = append(sans, "URI:"+uri.String())
		}
		fmt.Printf("                %s\n", strings.Join(sans, ", "))
	}

	// CRL Distribution Points (OID 2.5.29.31)
	if len(cert.CRLDistributionPoints) > 0 {
		fmt.Printf("            X509v3 CRL Distribution Points:\n")
		fmt.Printf("                Full Name:\n")
		for _, dp := range cert.CRLDistributionPoints {
			fmt.Printf("                  URI:%s\n", dp)
		}
	}

	// Authority Information Access (OCSP / CA Issuers)
	if len(cert.OCSPServer) > 0 || len(cert.IssuingCertificateURL) > 0 {
		fmt.Printf("            Authority Information Access:\n")
		for _, ocsp := range cert.OCSPServer {
			fmt.Printf("                OCSP - URI:%s\n", ocsp)
		}
		for _, issuer := range cert.IssuingCertificateURL {
			fmt.Printf("                CA Issuers - URI:%s\n", issuer)
		}
	}

	fmt.Printf("    SHA1 Fingerprint=%s\n", sha1Fingerprint(der))
	fmt.Println()
}

func parseCerts(pemData string) ([]*x509.Certificate, [][]byte) {
	var certs []*x509.Certificate
	var ders [][]byte
	rest := []byte(pemData)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: skipping unparseable certificate: %v\n", err)
			continue
		}
		certs = append(certs, cert)
		ders = append(ders, block.Bytes)
	}
	return certs, ders
}

func getCurrentNamespace(config clientcmd.ClientConfig) string {
	ns, _, err := config.Namespace()
	if err != nil || ns == "" {
		return "default"
	}
	return ns
}

// loadFromFile reads a local file and returns its certificate data as a key→PEM map.
// It accepts two formats:
//   - Raw PEM file: the entire file is treated as one bundle, keyed by the filename.
//   - ConfigMap YAML: the "data" field is extracted and returned as-is.
func loadFromFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	content := strings.TrimSpace(string(raw))

	// Raw PEM bundle — no YAML wrapper
	if strings.HasPrefix(content, "-----BEGIN") {
		return map[string]string{filepath.Base(path): content}, nil
	}

	// ConfigMap YAML
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	if len(cm.Data) == 0 {
		return nil, fmt.Errorf("no 'data' field found in YAML (is this a ConfigMap?)")
	}
	return cm.Data, nil
}

func main() {
	var (
		namespace     string
		configmapName string
		dataKey       string
		localFile     string
		showSubject   bool
		showIssuer    bool
		showDates     bool
		showSerial    bool
		showFP        bool
	)

	flag.StringVar(&namespace, "namespace", "", "Kubernetes namespace (default: current context namespace)")
	flag.StringVar(&namespace, "n", "", "Kubernetes namespace (shorthand for -namespace)")
	flag.StringVar(&configmapName, "configmap", "", "ConfigMap name")
	flag.StringVar(&configmapName, "cm", "", "ConfigMap name (shorthand for -configmap)")
	flag.StringVar(&dataKey, "key", "", "Specific data key to inspect (default: all keys with PEM data)")
	flag.StringVar(&localFile, "file", "", "Read from a local file instead of a cluster (ConfigMap YAML or raw PEM)")
	flag.StringVar(&localFile, "f", "", "Shorthand for -file")
	flag.BoolVar(&showSubject, "subject", false, "Show certificate subject")
	flag.BoolVar(&showIssuer, "issuer", false, "Show certificate issuer")
	flag.BoolVar(&showDates, "dates", false, "Show validity dates (notBefore / notAfter)")
	flag.BoolVar(&showSerial, "serial", false, "Show serial number")
	flag.BoolVar(&showFP, "fingerprint", false, "Show SHA1 fingerprint")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  %s [--namespace|-n <namespace>] --configmap|-cm <name> [OPTIONS]
  %s --file|-f <path> [OPTIONS]

Shows OpenSSL-style certificate information from a Kubernetes ConfigMap CA bundle
or a local file. When no field option is given, full OpenSSL-style text is shown.

Source (one required):
  -cm, -configmap  <name> ConfigMap name (reads from cluster)
  -f,  -file       <path> Local file: ConfigMap YAML or raw PEM bundle

Cluster options (only with -cm):
  -n, -namespace   <ns>   Kubernetes namespace (default: current context namespace)
  -key             <key>  Specific data key to inspect (default: all keys)

Output options:
  -subject                Show certificate subject
  -issuer                 Show certificate issuer
  -dates                  Show validity dates (notBefore / notAfter)
  -serial                 Show serial number
  -fingerprint            Show SHA1 fingerprint

  (combine freely: -subject -dates -fingerprint)

Examples:
  %s -cm trusted-ca
  %s -n kube-system -cm trusted-ca -dates
  %s -cm trusted-ca -subject -issuer -dates
  %s -cm trusted-ca -key ca-bundle.crt -fingerprint
  %s -f trusted-ca.yaml
  %s -f trusted-ca.yaml -dates
  %s -f ca-bundle.crt -subject -fingerprint
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
	}

	flag.Parse()

	if localFile == "" && configmapName == "" {
		fmt.Fprintln(os.Stderr, "error: provide -file/-f <path> or -configmap/-cm <name>")
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	// --- Load certificate data from file or cluster ---
	var cmData map[string]string
	var source string // used in section headers

	if localFile != "" {
		var err error
		cmData, err = loadFromFile(localFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		source = localFile
	} else {
		// Build kubeconfig from default rules (KUBECONFIG env or ~/.kube/config)
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules,
			&clientcmd.ConfigOverrides{},
		)

		if namespace == "" {
			namespace = getCurrentNamespace(kubeConfig)
		}

		restConfig, err := kubeConfig.ClientConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error building kubeconfig: %v\n", err)
			os.Exit(1)
		}

		clientset, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating kubernetes client: %v\n", err)
			os.Exit(1)
		}

		cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(
			context.Background(), configmapName, metav1.GetOptions{},
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error fetching configmap %q in namespace %q: %v\n",
				configmapName, namespace, err)
			os.Exit(1)
		}

		if len(cm.Data) == 0 {
			fmt.Fprintf(os.Stderr, "configmap %q/%q has no string data\n", namespace, configmapName)
			os.Exit(1)
		}

		cmData = cm.Data
		source = namespace + "/" + configmapName
	}

	// Collect keys to process (sorted for deterministic output)
	var keys []string
	if dataKey != "" {
		if _, ok := cmData[dataKey]; !ok {
			fmt.Fprintf(os.Stderr, "key %q not found in %q\n", dataKey, source)
			os.Exit(1)
		}
		keys = []string{dataKey}
	} else {
		for k := range cmData {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}

	showFields := showSubject || showIssuer || showDates || showSerial || showFP

	totalCerts := 0
	for _, key := range keys {
		certs, ders := parseCerts(cmData[key])
		if len(certs) == 0 {
			continue
		}

		fmt.Printf("=== %s  key: %s  (%d certificate(s)) ===\n\n",
			source, key, len(certs))

		for i, cert := range certs {
			totalCerts++

			if showFields {
				fmt.Printf("Certificate [%d]:\n", totalCerts)
				if showSubject {
					fmt.Printf("subject=%s\n", formatDN(cert.Subject))
				}
				if showIssuer {
					fmt.Printf("issuer=%s\n", formatDN(cert.Issuer))
				}
				if showDates {
					fmt.Printf("notBefore=%s\n", opensslTime(cert.NotBefore))
					fmt.Printf("notAfter=%s\n", opensslTime(cert.NotAfter))
				}
				if showSerial {
					fmt.Printf("serial=%s\n", serialHex(cert.SerialNumber))
				}
				if showFP {
					fmt.Printf("SHA1 Fingerprint=%s\n", sha1Fingerprint(ders[i]))
				}
				fmt.Println()
			} else {
				printCertFull(totalCerts, key, cert, ders[i])
			}
		}
	}

	if totalCerts == 0 {
		fmt.Fprintf(os.Stderr, "no valid PEM certificates found in configmap %q/%q\n",
			namespace, configmapName)
		os.Exit(1)
	}

	fmt.Printf("Total: %d certificate(s)\n", totalCerts)
}
