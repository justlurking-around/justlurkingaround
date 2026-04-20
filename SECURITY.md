# Security Policy

## Responsible Use

AI Secret Scanner is a **security research tool** intended for:
- Security researchers studying credential exposure
- Organizations monitoring their own repositories
- Developers learning about secret management best practices
- Open-source contributors improving the detection capabilities

## What To Do If You Find a Live Secret

If this scanner helps you discover a live credential in a public repository:

1. **Do NOT access** any systems using that credential
2. **Do NOT store** the credential
3. **Notify the repository owner** — open a private vulnerability report or email them
4. **Report to the provider** — most providers have bug bounty or responsible disclosure programs:
   - GitHub: security@github.com
   - AWS: aws-security@amazon.com
   - Google: https://bughunters.google.com
   - Stripe: https://stripe.com/docs/security
   - Slack: https://api.slack.com/security

## Reporting Vulnerabilities in This Tool

If you find a vulnerability **in ai-secret-scanner itself**:

Please **do not** open a public GitHub issue. Instead:
1. Open a [GitHub Security Advisory](https://github.com/justlurking-around/justlurkingaround/security/advisories/new)
2. Include a description of the issue, reproduction steps, and potential impact

We will respond within 48 hours and work with you on a fix and disclosure timeline.

## Disclaimer

This tool is provided for educational and research purposes. The authors are not responsible for misuse. Always obtain proper authorization before scanning repositories you do not own.
