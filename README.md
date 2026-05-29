# dmarcation

A simple DMARC validator, written in PHP and React, with dependency-free CSS. It's deployed on Railway and accessible via dmarcation.jonathanleist.com.

## Usage

Install dependencies with [Composer](https://getcomposer.org/):

```bash
composer install
```

Validate a DMARC record string:

```bash
php bin/dmarcation validate "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

Look up and validate the record published for a domain (optionally querying a specific nameserver):

```bash
php bin/dmarcation lookup example.com
php bin/dmarcation lookup sub.example.com --ns=1.1.1.1
```

You can also pipe a record in via standard input, and `php bin/dmarcation --help` prints full usage.

Exit codes:

| Code | Meaning |
| ---- | ------- |
| `0`  | The record is valid (warnings may still be present) |
| `1`  | The record is invalid, missing, or duplicated |
| `2`  | Usage error |
| `3`  | DNS lookup failed |

## License

Distributed under the [Apache-2.0](LICENSE) license.

## Acknowledgements

This project gratefully builds on the work of others:

- [Dracula](https://draculatheme.com/) — the color scheme used by the web terminal interface.
- [Net_DNS2](https://github.com/mikepultz/netdns2) — pure-PHP DNS resolver used for record lookups.
- [php-domain-parser](https://github.com/jeremykendall/php-domain-parser) — resolves organizational domains for DMARC policy inheritance.
- [Public Suffix List](https://publicsuffix.org/) — Mozilla's list of public suffixes, bundled to determine domain boundaries.
