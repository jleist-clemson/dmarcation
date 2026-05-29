<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

/**
 * A single problem discovered while validating a DMARC record.
 */
final readonly class ValidationIssue
{
    public function __construct(
        public Severity $severity,
        public string $message,
        public ?string $tag = null,
    ) {
    }

    public function __toString(): string
    {
        $prefix = strtoupper($this->severity->value);
        $location = $this->tag !== null ? sprintf(' [%s]', $this->tag) : '';

        return sprintf('%s%s: %s', $prefix, $location, $this->message);
    }
}
