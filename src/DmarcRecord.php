<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

final class DmarcRecord
{
    /** Policy values valid for the p and sp tags. */
    private const POLICIES = ['none', 'quarantine', 'reject'];

    /** Alignment modes valid for the adkim and aspf tags. */
    private const ALIGNMENTS = ['r', 's'];

    /** Failure reporting options valid for the fo tag. */
    private const FAILURE_OPTIONS = ['0', '1', 'd', 's'];

    /** Maximum value for the ri tag (unsigned 32-bit integer). */
    private const MAX_REPORT_INTERVAL = 4294967295;

    private string $raw;
    private array $tags = [];
    private array $order = [];
    private array $parseIssues = [];

    public function __construct(string $record)
    {
        $this->raw = $record;
        $this->parse();
    }

    /**
     * Create a new DmarcRecord from a string.
     * 
     * @param string $record
     *
     * @return self
     */
    public static function fromString(string $record): self
    {
        return new self($record);
    }

    /**
     * Get the tags from the record.
     * 
     * @return array
     */
    public function getTags(): array
    {
        return $this->tags;
    }

    /**
     * Get the raw record.
     * 
     * @return string
     */
    public function getRaw(): string
    {
        return $this->raw;
    }

    /**
     * Validate the record and return the collected errors and warnings.
     * 
     * @return ValidationResult
     */
    public function validate(): ValidationResult
    {
        $result = new ValidationResult();
        $result->setTags($this->tags);

        if (trim($this->raw) === '') {
            $result->addError('The DMARC record is empty.');

            return $result;
        }

        foreach ($this->parseIssues as $issue) {
            $result->addIssue($issue);
        }

        $this->validateVersion($result);
        $this->validatePolicyPresence($result);

        foreach ($this->tags as $tag => $value) {
            $this->validateTagValue($tag, $value, $result);
        }

        $this->validateCrossTagRules($result);

        return $result;
    }

    /**
     * Split the raw record into tag=value pairs, recording any structural
     * problems (malformed pairs, duplicate tags) as we go.
     * 
     * @return void
     */
    private function parse(): void
    {
        $record = trim($this->raw);

        // TXT records are frequently quoted when copied from DNS tools; tolerate
        // a single surrounding pair of double quotes.
        if (strlen($record) >= 2 && str_starts_with($record, '"') && str_ends_with($record, '"')) {
            $record = substr($record, 1, -1);
        }

        foreach (explode(';', $record) as $component) {
            $component = trim($component);
            if ($component === '') {
                continue;
            }

            if (!str_contains($component, '=')) {
                $this->parseIssues[] = new ValidationIssue(
                    Severity::Error,
                    sprintf("Malformed component '%s'; expected 'tag=value'.", $component)
                );
                continue;
            }

            [$name, $value] = explode('=', $component, 2);
            $name = strtolower(trim($name));
            $value = trim($value);

            if ($name === '') {
                $this->parseIssues[] = new ValidationIssue(Severity::Error, 'Found a value with an empty tag name.');
                continue;
            }

            if (isset($this->tags[$name])) {
                $this->parseIssues[] = new ValidationIssue(
                    Severity::Error,
                    sprintf("Duplicate tag '%s'; only the first occurrence is used.", $name),
                    $name
                );
                continue;
            }

            $this->tags[$name] = $value;
            $this->order[] = $name;
        }
    }

    /**
     * Validate the version tag.
     * 
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validateVersion(ValidationResult $result): void
    {
        if (!isset($this->tags['v'])) {
            $result->addError("Missing required 'v' tag; the record must begin with 'v=DMARC1'.", 'v');

            return;
        }

        if (($this->order[0] ?? null) !== 'v') {
            $result->addError("The 'v' tag must be the very first tag in the record.", 'v');
        }

        if ($this->tags['v'] !== 'DMARC1') {
            $result->addError(
                sprintf("The 'v' tag must be exactly 'DMARC1' (case-sensitive), got '%s'.", $this->tags['v']),
                'v'
            );
        }
    }

    /**
     * Validate the policy presence.
     * 
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validatePolicyPresence(ValidationResult $result): void
    {
        if (!isset($this->tags['p'])) {
            $result->addError("Missing required 'p' tag (the requested policy: none, quarantine, or reject).", 'p');

            return;
        }

        // RFC 7489: the p tag must immediately follow the v tag.
        if (($this->order[1] ?? null) !== 'p') {
            $result->addWarning("The 'p' tag should appear immediately after the 'v' tag.", 'p');
        }
    }

    /**
     * Validate the value of a tag.
     * 
     * @param string $tag
     * @param string $value
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validateTagValue(string $tag, string $value, ValidationResult $result): void
    {
        match ($tag) {
            'v' => null, // Handled by validateVersion().
            'p', 'sp' => $this->validatePolicy($tag, $value, $result),
            'adkim', 'aspf' => $this->validateAlignment($tag, $value, $result),
            'fo' => $this->validateFailureOptions($value, $result),
            'pct' => $this->validatePercent($value, $result),
            'ri' => $this->validateReportInterval($value, $result),
            'rf' => $this->validateReportFormat($value, $result),
            'rua', 'ruf' => $this->validateUriList($tag, $value, $result),
            default => $result->addWarning(
                sprintf("Unknown tag '%s'; receivers are required to ignore it.", $tag),
                $tag
            ),
        };
    }

    /**
     * Validate the policy value.
     * 
     * @param string $tag
     * @param string $value
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validatePolicy(string $tag, string $value, ValidationResult $result): void
    {
        if (!in_array($value, self::POLICIES, true)) {
            $result->addError(
                sprintf("Invalid '%s' value '%s'; must be one of: %s.", $tag, $value, implode(', ', self::POLICIES)),
                $tag
            );
        }
    }

    /**
     * Validate the alignment value.
     * 
     * @param string $tag
     * @param string $value
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validateAlignment(string $tag, string $value, ValidationResult $result): void
    {
        if (!in_array($value, self::ALIGNMENTS, true)) {
            $result->addError(
                sprintf("Invalid '%s' value '%s'; must be 'r' (relaxed) or 's' (strict).", $tag, $value),
                $tag
            );
        }
    }

    /**
     * Validate the failure options.
     * 
     * @param string $value
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validateFailureOptions(string $value, ValidationResult $result): void
    {
        if ($value === '') {
            $result->addError("The 'fo' tag must not be empty.", 'fo');

            return;
        }

        foreach (explode(':', $value) as $option) {
            if (!in_array($option, self::FAILURE_OPTIONS, true)) {
                $result->addError(
                    sprintf(
                        "Invalid 'fo' option '%s'; allowed values are %s (colon-separated).",
                        $option,
                        implode(', ', self::FAILURE_OPTIONS)
                    ),
                    'fo'
                );
            }
        }
    }

    /**
     * Validate the percent value.
     * 
     * @param string $value
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validatePercent(string $value, ValidationResult $result): void
    {
        if ($value === '' || !ctype_digit($value)) {
            $result->addError(sprintf("The 'pct' tag must be an integer from 0 to 100, got '%s'.", $value), 'pct');

            return;
        }

        $pct = (int) $value;
        if ($pct > 100) {
            $result->addError(sprintf("The 'pct' tag must be from 0 to 100, got %d.", $pct), 'pct');
        }
    }

    /**
     * Validate the report interval value.
     * 
     * @param string $value
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validateReportInterval(string $value, ValidationResult $result): void
    {
        if ($value === '' || !ctype_digit($value)) {
            $result->addError(sprintf("The 'ri' tag must be an unsigned integer, got '%s'.", $value), 'ri');

            return;
        }

        if ((int) $value > self::MAX_REPORT_INTERVAL) {
            $result->addError(
                sprintf("The 'ri' tag must not exceed %d (32-bit unsigned), got %s.", self::MAX_REPORT_INTERVAL, $value),
                'ri'
            );
        }
    }

    /**
     * Validate the report format value.
     * 
     * @param string $value
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validateReportFormat(string $value, ValidationResult $result): void
    {
        if ($value === '') {
            $result->addError("The 'rf' tag must not be empty.", 'rf');

            return;
        }

        foreach (explode(':', $value) as $format) {
            if (strtolower($format) !== 'afrf') {
                $result->addWarning(
                    sprintf("Unrecognized 'rf' report format '%s'; only 'afrf' is widely supported.", $format),
                    'rf'
                );
            }
        }
    }

    /**
     * Validate the URI list value.
     * 
     * @param string $tag
     * @param string $value
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validateUriList(string $tag, string $value, ValidationResult $result): void
    {
        if ($value === '') {
            $result->addError(sprintf("The '%s' tag must list at least one reporting URI.", $tag), $tag);

            return;
        }

        foreach (explode(',', $value) as $uri) {
            $this->validateUri($tag, trim($uri), $result);
        }
    }

    /**
     * Validate a single URI.
     * 
     * @param string $tag
     * @param string $uri
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validateUri(string $tag, string $uri, ValidationResult $result): void
    {
        if ($uri === '') {
            $result->addError(sprintf("Empty reporting URI in the '%s' tag.", $tag), $tag);

            return;
        }

        // An optional "!" introduces a maximum report size, e.g. mailto:a@b!10m.
        if (str_contains($uri, '!')) {
            [$uri, $size] = explode('!', $uri, 2);
            if (preg_match('/^\d+[kmgt]?$/i', $size) !== 1) {
                $result->addError(
                    sprintf("Invalid size limit '!%s' in '%s'; expected digits with an optional k/m/g/t unit.", $size, $tag),
                    $tag
                );
            }
        }

        if (!str_contains($uri, ':')) {
            $result->addError(
                sprintf("Reporting URI '%s' in '%s' is missing a scheme (e.g. 'mailto:').", $uri, $tag),
                $tag
            );

            return;
        }

        [$scheme, $rest] = explode(':', $uri, 2);
        $scheme = strtolower($scheme);

        if ($scheme !== 'mailto') {
            $result->addWarning(
                sprintf("Reporting URI scheme '%s' in '%s' is unusual; 'mailto' is expected.", $scheme, $tag),
                $tag
            );

            return;
        }

        if (filter_var($rest, FILTER_VALIDATE_EMAIL) === false) {
            $result->addError(
                sprintf("'%s' in '%s' is not a valid mailto address.", $rest, $tag),
                $tag
            );
        }
    }

    /**
     * Rules that depend on the relationship between multiple tags.
     * 
     * @param ValidationResult $result
     *
     * @return void
     */
    private function validateCrossTagRules(ValidationResult $result): void
    {
        // Failure reporting options only take effect when a failure report
        // destination (ruf) is configured.
        if (isset($this->tags['fo']) && !isset($this->tags['ruf'])) {
            $result->addWarning("The 'fo' tag has no effect without a 'ruf' tag to receive failure reports.", 'fo');
        }

        // sp is only meaningful at an organizational domain's record.
        if (isset($this->tags['sp']) && !isset($this->tags['p'])) {
            $result->addWarning("The 'sp' tag is ignored unless a 'p' tag is also present.", 'sp');
        }
    }
}
