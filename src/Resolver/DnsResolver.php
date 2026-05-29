<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Resolver;

/**
 * Abstraction over a DNS resolver. Keeping this behind an interface lets the
 * rest of the library stay independent of any particular DNS backend and makes
 * it trivial to substitute a fake resolver in tests.
 */
interface DnsResolver
{
    /**
     * Return every TXT record published at the given hostname.
     *
     * Multi-string TXT records are concatenated into a single string per
     * record, as required for DMARC. A hostname that does not exist (NXDOMAIN)
     * or has no TXT records yields an empty array rather than an exception.
     *
     * @return list<string>
     *
     * @throws ResolverException When the lookup cannot be completed (network
     *                           error, timeout, SERVFAIL, etc.).
     */
    public function txtRecords(string $hostname): array;
}
