<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Tests\Doubles;

use Jonathanleist\Dmarcation\Resolver\DnsResolver;
use Jonathanleist\Dmarcation\Resolver\ResolverException;

/**
 * In-memory DnsResolver for tests: returns canned TXT records per hostname and
 * can be told to throw for a specific hostname to simulate a lookup failure.
 */
final class FakeDnsResolver implements DnsResolver
{
    /**
     * @param array<string, list<string>> $records   hostname => TXT records
     * @param string|null                  $failsFor  hostname that should throw
     */
    public function __construct(
        private readonly array $records = [],
        private readonly ?string $failsFor = null,
    ) {
    }

    public function txtRecords(string $hostname): array
    {
        if ($this->failsFor !== null && $hostname === $this->failsFor) {
            throw new ResolverException(sprintf('simulated DNS failure for %s', $hostname));
        }

        return $this->records[$hostname] ?? [];
    }
}
