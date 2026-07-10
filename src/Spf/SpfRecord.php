<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Spf;

use Jonathanleist\Dmarcation\Severity;
use Jonathanleist\Dmarcation\ValidationIssue;
use Jonathanleist\Dmarcation\ValidationResult;

/**
 * Parses and syntactically validates an SPF (Sender Policy Framework) record
 * per RFC 7208.
 *
 * Validation here is purely lexical/structural: the record's version, the
 * mechanisms and modifiers it contains, and their arguments. The RFC 7208
 * §4.6.4 limit of 10 DNS lookups can only be enforced by actually following
 * include:/redirect= references, which is the job of {@see SpfEvaluator}.
 */
final class SpfRecord
{
    /** Qualifier characters that may prefix a mechanism. */
    private const QUALIFIERS = ['+', '-', '~', '?'];

    /** The one true SPF version string (compared case-insensitively). */
    private const VERSION = 'spf1';

    /** RFC 7208 §4.6.4: the maximum number of DNS-querying terms. */
    public const LOOKUP_LIMIT = 10;

    private string $raw;

    /** @var list<SpfTerm> */
    private array $terms = [];

    private ?string $version = null;
    private int $versionCount = 0;
    private bool $versionFirst = false;

    /** @var list<ValidationIssue> */
    private array $parseIssues = [];

    public function __construct(string $record)
    {
        $this->raw = $record;
        $this->parse();
    }

    public static function fromString(string $record): self
    {
        return new self($record);
    }

    public function getRaw(): string
    {
        return $this->raw;
    }

    /**
     * @return list<SpfTerm>
     */
    public function getTerms(): array
    {
        return $this->terms;
    }

    /**
     * The value found after "v=" (e.g. "spf1"), or null if no version tag was
     * present.
     */
    public function getVersion(): ?string
    {
        return $this->version;
    }

    /**
     * The number of top-level terms that trigger a DNS lookup. This is a lower
     * bound on the full recursive count computed by {@see SpfEvaluator}.
     */
    public function countLookupTerms(): int
    {
        $count = 0;
        foreach ($this->terms as $term) {
            if ($term->causesLookup()) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Validate the record and return the collected errors and warnings.
     */
    public function validate(): ValidationResult
    {
        $result = new ValidationResult();

        if (trim($this->raw) === '') {
            $result->addError('The SPF record is empty.');

            return $result;
        }

        foreach ($this->parseIssues as $issue) {
            $result->addIssue($issue);
        }

        $this->validateVersion($result);

        foreach ($this->terms as $term) {
            if ($term->isModifier) {
                $this->validateModifier($term, $result);
            } else {
                $this->validateMechanism($term, $result);
            }
        }

        $this->validateCrossTermRules($result);

        return $result;
    }

    /**
     * Split the record into whitespace-separated terms, pulling out the version
     * tag and classifying each remaining term as a mechanism or a modifier.
     */
    private function parse(): void
    {
        $record = trim($this->raw);

        // Tolerate a single surrounding pair of double quotes, as DNS tools
        // frequently render TXT records quoted.
        if (strlen($record) >= 2 && str_starts_with($record, '"') && str_ends_with($record, '"')) {
            $record = substr($record, 1, -1);
        }

        if ($record === '') {
            return;
        }

        $parts = preg_split('/\s+/', $record) ?: [];
        $this->versionFirst = isset($parts[0]) && preg_match('/^v=/i', $parts[0]) === 1;

        foreach ($parts as $part) {
            if ($part === '') {
                continue;
            }

            // The version tag looks like a modifier (v=spf1) but is special.
            if (preg_match('/^v=/i', $part) === 1) {
                $this->versionCount++;
                if ($this->version === null) {
                    $this->version = substr($part, 2);
                }
                continue;
            }

            $this->terms[] = $this->parseTerm($part);
        }
    }

    /**
     * Classify a single term as a modifier (name=value) or a mechanism.
     */
    private function parseTerm(string $part): SpfTerm
    {
        // A modifier is name=value and never carries a qualifier. Mechanism
        // arguments never contain '=', so its presence is unambiguous.
        if (preg_match('/^([a-z][a-z0-9._-]*)=(.*)$/i', $part, $matches) === 1) {
            return new SpfTerm($part, true, null, strtolower($matches[1]), $matches[2]);
        }

        $qualifier = null;
        $body = $part;
        if ($body !== '' && in_array($body[0], self::QUALIFIERS, true)) {
            $qualifier = $body[0];
            $body = substr($body, 1);
        }

        // The mechanism name is the leading alphanumeric run; the remainder
        // (starting with ':' or '/') is the argument.
        if (preg_match('/^([a-z0-9]+)(.*)$/i', $body, $matches) === 1) {
            $name = strtolower($matches[1]);
            $value = $matches[2] === '' ? null : $matches[2];
        } else {
            $name = strtolower($body);
            $value = null;
        }

        return new SpfTerm($part, false, $qualifier, $name, $value);
    }

    private function validateVersion(ValidationResult $result): void
    {
        if ($this->versionCount === 0) {
            $result->addError("Missing version tag; the record must begin with 'v=spf1'.", 'v');

            return;
        }

        if (!$this->versionFirst) {
            $result->addError("The 'v=spf1' version tag must be the first term in the record.", 'v');
        }

        if ($this->versionCount > 1) {
            $result->addError("The 'v=spf1' version tag must appear exactly once.", 'v');
        }

        if (strtolower((string) $this->version) !== self::VERSION) {
            $result->addError(
                sprintf("Unsupported SPF version 'v=%s'; only 'v=spf1' is defined.", $this->version),
                'v'
            );
        }
    }

    private function validateMechanism(SpfTerm $term, ValidationResult $result): void
    {
        match ($term->name) {
            'all' => $this->validateAll($term, $result),
            'include', 'exists' => $this->validateDomainMechanism($term, $result),
            'a', 'mx' => $this->validateDualCidrMechanism($term, $result),
            'ptr' => $this->validatePtr($term, $result),
            'ip4' => $this->validateIp($term, 4, $result),
            'ip6' => $this->validateIp($term, 6, $result),
            default => $result->addError(
                sprintf("Unknown mechanism '%s'.", $term->raw),
                $term->name
            ),
        };
    }

    private function validateAll(SpfTerm $term, ValidationResult $result): void
    {
        if ($term->value !== null) {
            $result->addError("The 'all' mechanism does not take an argument.", 'all');
        }
    }

    /**
     * include: and exists: both require a domain argument introduced by ':'.
     */
    private function validateDomainMechanism(SpfTerm $term, ValidationResult $result): void
    {
        $domain = $term->value !== null && str_starts_with($term->value, ':') ? substr($term->value, 1) : null;

        if ($domain === null || $domain === '') {
            $result->addError(
                sprintf("The '%s' mechanism requires a domain (e.g. %s:example.com).", $term->name, $term->name),
                $term->name
            );

            return;
        }

        $this->validateDomainSpec($domain, $term->name, $result);
    }

    /**
     * a and mx accept an optional ":domain" and an optional dual CIDR length
     * ("/32", "//128", or "/32//128").
     */
    private function validateDualCidrMechanism(SpfTerm $term, ValidationResult $result): void
    {
        if ($term->value === null) {
            return; // Bare "a"/"mx" means "the current domain".
        }

        $value = $term->value;
        $cidrSpec = null;

        if (str_starts_with($value, ':')) {
            $rest = substr($value, 1);
            $slash = strpos($rest, '/');
            if ($slash === false) {
                $domain = $rest;
            } else {
                $domain = substr($rest, 0, $slash);
                $cidrSpec = substr($rest, $slash);
            }

            if ($domain === '') {
                $result->addError(sprintf("The '%s' mechanism has an empty domain.", $term->name), $term->name);
            } else {
                $this->validateDomainSpec($domain, $term->name, $result);
            }
        } elseif (str_starts_with($value, '/')) {
            $cidrSpec = $value;
        }

        if ($cidrSpec !== null) {
            $this->validateDualCidr($cidrSpec, $term->name, $result);
        }
    }

    private function validateDualCidr(string $cidrSpec, string $name, ValidationResult $result): void
    {
        if (preg_match('#^(?:/(\d+))?(?://(\d+))?$#', $cidrSpec, $matches) !== 1 || $cidrSpec === '/' || $cidrSpec === '//') {
            $result->addError(sprintf("Malformed CIDR length '%s' in the '%s' mechanism.", $cidrSpec, $name), $name);

            return;
        }

        if (($matches[1] ?? '') !== '' && (int) $matches[1] > 32) {
            $result->addError(sprintf("The IPv4 CIDR length in '%s' must be 0-32.", $name), $name);
        }

        if (($matches[2] ?? '') !== '' && (int) $matches[2] > 128) {
            $result->addError(sprintf("The IPv6 CIDR length in '%s' must be 0-128.", $name), $name);
        }
    }

    private function validatePtr(SpfTerm $term, ValidationResult $result): void
    {
        // RFC 7208 §5.5: ptr is deprecated and SHOULD NOT be used.
        $result->addWarning("The 'ptr' mechanism is deprecated (RFC 7208 §5.5) and should not be used.", 'ptr');

        if ($term->value !== null && str_starts_with($term->value, ':')) {
            $this->validateDomainSpec(substr($term->value, 1), 'ptr', $result);
        }
    }

    private function validateIp(SpfTerm $term, int $version, ValidationResult $result): void
    {
        $name = 'ip' . $version;

        if ($term->value === null || !str_starts_with($term->value, ':')) {
            $result->addError(
                sprintf("The '%s' mechanism requires an address (e.g. %s).", $name, $version === 4 ? 'ip4:192.0.2.0/24' : 'ip6:2001:db8::/32'),
                $name
            );

            return;
        }

        $address = substr($term->value, 1);
        $cidr = null;

        // IPv6 addresses contain ':', so only split on the LAST '/'.
        $slash = strrpos($address, '/');
        if ($slash !== false) {
            $cidr = substr($address, $slash + 1);
            $address = substr($address, 0, $slash);
        }

        $flag = $version === 4 ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;
        if (filter_var($address, FILTER_VALIDATE_IP, $flag) === false) {
            $result->addError(sprintf("'%s' is not a valid IPv%d address.", $address, $version), $name);
        }

        if ($cidr !== null) {
            $max = $version === 4 ? 32 : 128;
            if ($cidr === '' || !ctype_digit($cidr) || (int) $cidr > $max) {
                $result->addError(sprintf("Invalid CIDR prefix '/%s' in '%s'; must be 0-%d.", $cidr, $name, $max), $name);
            }
        }
    }

    private function validateModifier(SpfTerm $term, ValidationResult $result): void
    {
        match ($term->name) {
            'redirect', 'exp' => $this->validateDomainSpec((string) $term->value, $term->name, $result, true),
            default => $result->addWarning(
                sprintf("Unknown modifier '%s'; receivers must ignore unrecognized modifiers.", $term->name),
                $term->name
            ),
        };
    }

    /**
     * Validate a domain-spec argument. Domains containing macros (%{...}) are
     * accepted without further scrutiny; otherwise a light hostname check flags
     * obviously malformed values.
     */
    private function validateDomainSpec(string $domain, string $label, ValidationResult $result, bool $required = false): void
    {
        if ($domain === '') {
            if ($required) {
                $result->addError(sprintf("The '%s' modifier requires a domain.", $label), $label);
            }

            return;
        }

        // Macros are expanded at evaluation time; don't second-guess them here.
        if (str_contains($domain, '%')) {
            return;
        }

        if (preg_match('/^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i', $domain) !== 1) {
            $result->addWarning(sprintf("'%s' in '%s' does not look like a valid domain name.", $domain, $label), $label);
        }
    }

    /**
     * Rules that depend on the record as a whole: term ordering, duplicate
     * modifiers, the lookup budget, and common foot-guns.
     */
    private function validateCrossTermRules(ValidationResult $result): void
    {
        $allIndex = null;
        $redirectCount = 0;
        $expCount = 0;
        $hasAll = false;
        $hasRedirect = false;

        foreach ($this->terms as $index => $term) {
            if ($term->isMechanism() && $term->name === 'all') {
                $hasAll = true;
                if ($allIndex === null) {
                    $allIndex = $index;
                }

                if ($term->effectiveQualifier() === '+') {
                    $result->addWarning(
                        "The '+all' mechanism authorizes every host on the internet to send as your domain.",
                        'all'
                    );
                }
            }

            if ($term->isModifier && $term->name === 'redirect') {
                $redirectCount++;
                $hasRedirect = true;
            }

            if ($term->isModifier && $term->name === 'exp') {
                $expCount++;
            }
        }

        // Anything after the first 'all' can never be reached.
        if ($allIndex !== null && $allIndex < count($this->terms) - 1) {
            $result->addWarning("Terms after the 'all' mechanism are unreachable and ignored.", 'all');
        }

        if ($redirectCount > 1) {
            $result->addError("The 'redirect' modifier must not appear more than once.", 'redirect');
        }

        if ($expCount > 1) {
            $result->addError("The 'exp' modifier must not appear more than once.", 'exp');
        }

        if ($hasRedirect && $hasAll) {
            $result->addWarning("The 'redirect' modifier is ignored when an 'all' mechanism is present.", 'redirect');
        }

        if (!$hasAll && !$hasRedirect && $this->terms !== []) {
            $result->addWarning(
                "The record has no 'all' mechanism or 'redirect' modifier; unmatched senders default to '?all' (neutral).",
                'all'
            );
        }

        $lookupTerms = $this->countLookupTerms();
        if ($lookupTerms > self::LOOKUP_LIMIT) {
            $result->addError(
                sprintf(
                    'The record already uses %d DNS-lookup mechanisms at the top level; RFC 7208 allows at most %d (including nested includes).',
                    $lookupTerms,
                    self::LOOKUP_LIMIT
                )
            );
        }
    }
}
