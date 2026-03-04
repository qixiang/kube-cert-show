# kube-cert-show

Inspect X.509 certificates stored in a Kubernetes ConfigMap CA bundle — directly from the cluster or from a local file — with output styled after `openssl x509`.

## Features

- Reads certificates from a **live Kubernetes cluster** ConfigMap or a **local file** (ConfigMap YAML or raw PEM bundle)
- Displays **full OpenSSL-style text** per certificate (version, serial, issuer, subject, validity, key usage, extensions, fingerprint)
- Selectively shows only the fields you care about: **subject**, **issuer**, **dates**, **serial**, **fingerprint**
- Multiple fields can be combined freely, e.g. `-subject -dates -fingerprint`
- Handles CA bundles with **multiple concatenated certificates** in a single key
- Supports ConfigMaps with **multiple data keys** (iterates all by default, or target one with `-key`)

## Installation

### go install (recommended)

```bash
go install github.com/qixiang/kube-cert-show@latest
```

The binary is placed in `$GOPATH/bin` (or `$HOME/go/bin` by default). Make sure that directory is on your `$PATH`.

### Build from source

```bash
git clone https://github.com/qixiang/kube-cert-show.git
cd kube-cert-show
go build -o kube-cert-show .
mv kube-cert-show /usr/local/bin/
```

### kubectl plugin

Because the binary is named `kube-cert-show`, kubectl does **not** auto-discover it as a plugin (kubectl plugins must be named `kubectl-*`). In kubectl's plugin naming convention, underscores in the filename become hyphens in the subcommand, so to invoke it as `kubectl cert-show`, create a symlink named `kubectl-cert_show`:

```bash
ln -s /usr/local/bin/kube-cert-show /usr/local/bin/kubectl-cert_show
kubectl cert-show -cm trusted-ca
```

## Usage

```
kube-cert-show [--namespace|-n <namespace>] --configmap|-cm <name> [OPTIONS]
kube-cert-show --file|-f <path> [OPTIONS]
```

### Source flags (one required)

| Flag | Description |
|---|---|
| `-cm`, `-configmap <name>` | Read from a ConfigMap in the cluster |
| `-f`, `-file <path>` | Read from a local ConfigMap YAML or raw PEM file |

### Cluster flags (only with `-cm`)

| Flag | Description |
|---|---|
| `-n`, `-namespace <ns>` | Kubernetes namespace (default: current context namespace) |
| `-key <key>` | Specific data key to inspect (default: all keys) |

### Output flags

| Flag | Description |
|---|---|
| `-subject` | Show certificate subject |
| `-issuer` | Show certificate issuer |
| `-dates` | Show `notBefore` / `notAfter` |
| `-serial` | Show serial number |
| `-fingerprint` | Show SHA1 fingerprint |
| *(none)* | Show full OpenSSL-style text for every certificate |

Output flags can be combined freely.

## Examples

### From a cluster

```bash
# Full text for all certs in the ConfigMap (current namespace)
kube-cert-show -cm trusted-ca

# Specify namespace
kube-cert-show -n kube-system -cm trusted-ca

# Show only expiry dates — useful for finding expired/expiring CAs
kube-cert-show -cm trusted-ca -dates

# Show subject + issuer + dates together
kube-cert-show -cm trusted-ca -subject -issuer -dates

# Show SHA1 fingerprints only
kube-cert-show -cm trusted-ca -fingerprint

# Target a specific data key inside the ConfigMap
kube-cert-show -cm trusted-ca -key ca-bundle.crt -dates
```

### From a local file

```bash
# ConfigMap YAML (e.g. exported with: kubectl get cm trusted-ca -o yaml > trusted-ca.yaml)
kube-cert-show -f trusted-ca.yaml

# Show only dates from a local YAML
kube-cert-show -f trusted-ca.yaml -dates

# Raw PEM bundle file
kube-cert-show -f ca-bundle.crt -subject -fingerprint
```

## Example output

### Full text (default)

```
=== kube-system/trusted-ca  key: ca-bundle.crt  (130 certificate(s)) ===

Certificate [1]  (key: ca-bundle.crt)
─────────────────────────────────────
    Data:
        Version: 3 (0x2)
        Serial Number:
            a6:8b:79:29:00:00:00:00:50:d0:91:f9
        Signature Algorithm: ECDSA-SHA384
        Issuer: C = US, O = Entrust, Inc., CN = Entrust Root Certification Authority - EC1
        Validity
            Not Before: Dec 18 15:25:36 2012 GMT
            Not After : Dec 18 15:55:36 2037 GMT
        Subject: C = US, O = Entrust, Inc., CN = Entrust Root Certification Authority - EC1
        Subject Public Key Info:
            Public Key Algorithm: ECDSA
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                B7:63:E7:1A:DD:8D:E9:08:A6:55:83:A4:E0:6A:50:41:65:11:42:49
    SHA1 Fingerprint=20:D8:06:40:DF:9B:25:F5:12:25:3A:11:EA:F7:59:8A:EB:14:B5:47
```

### `-dates`

```
Certificate [1]:
notBefore=Dec 18 15:25:36 2012 GMT
notAfter=Dec 18 15:55:36 2037 GMT

Certificate [2]:
notBefore=Jan 29 14:06:06 2010 GMT
notAfter=Dec 31 14:06:06 2030 GMT
```

### `-subject -fingerprint`

```
Certificate [1]:
subject=C = US, O = Entrust, Inc., CN = Entrust Root Certification Authority - EC1
SHA1 Fingerprint=20:D8:06:40:DF:9B:25:F5:12:25:3A:11:EA:F7:59:8A:EB:14:B5:47
```

## Requirements

- Go 1.22+
- Access to a Kubernetes cluster via `~/.kube/config` or `$KUBECONFIG` (only needed when reading from a cluster)
