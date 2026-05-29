<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

/**
 * A single DNS query performed during DMARC discovery, together with the DMARC
 * records (those beginning with "v=DMARC1") found at that name.
 */
final readonly class LookupQuery
{
    /**
     * @param string       $name    The DNS name queried (e.g. _dmarc.example.com).
     * @param list<string> $records The DMARC records found at that name.
     */
    public function __construct(
        public string $name,
        public array $records,
    ) {
    }

    public function isUnique(): bool
    {
        return count($this->records) === 1;
    }

    public function hasMultiple(): bool
    {
        return count($this->records) > 1;
    }

    public function record(): ?string
    {
        return $this->isUnique() ? $this->records[0] : null;
    }
}
