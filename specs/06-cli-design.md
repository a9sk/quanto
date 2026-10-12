# 06 — CLI Design

```
quanto [command] [flags]

Commands:
  scan <target>      Scan a TLS endpoint.
  cert <file>        Analyze a certificate, chain, or key file.
  policy             Manage quantum-readiness policies.
    list             List built-in policies.
    show <name>      Show policy definition.
  version            Show version and supported algorithms.

Global flags:
  -o, --output text|json|yaml   Output format (default: text)
  -p, --policy <file|name>      Policy to apply (default: default)
  -t, --timeout <duration>      Connection timeout (default: 10s)
  -v, --verbose                 Include supported algorithms and extensions
  --insecure                    Skip certificate validation
  --sni <name>                  Override SNI
  --starttls <protocol>         Use STARTTLS (smtp, imap, pop3, ftp, xmpp, ldap)
  --client-cert <file>          Client certificate (PEM)
  --client-key <file>           Client private key (PEM)
  --ca-file <file>              Custom CA bundle
```
