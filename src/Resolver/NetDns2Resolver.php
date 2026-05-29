<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Resolver;

use NetDNS2\ENUM\Error;
use NetDNS2\Exception as NetDns2Exception;
use NetDNS2\Resolver;
use NetDNS2\RR\TXT;

/**
 * A {@see DnsResolver} backed by the NetDNS2 library.
 *
 * By default it uses the system resolver configuration (/etc/resolv.conf), but
 * specific nameservers can be supplied for deterministic, sandboxed lookups.
 */
final class NetDns2Resolver implements DnsResolver
{
    private Resolver $resolver;

    /**
     * @param list<string> $nameservers Nameservers to query (e.g. ['1.1.1.1']);
     *                                   empty to use the system configuration.
     * @param float        $timeout     Per-query socket timeout in seconds.
     */
    public function __construct(array $nameservers = [], float $timeout = 5.0)
    {
        $options = ['timeout' => $timeout];
        if ($nameservers !== []) {
            $options['nameservers'] = $nameservers;
        }

        $this->resolver = new Resolver($options);
    }

    public function txtRecords(string $hostname): array
    {
        try {
            $response = $this->resolver->query($hostname, 'TXT');
        } catch (NetDns2Exception $e) {
            // A non-existent name simply means there is no record to validate.
            if ($e->getCode() === Error::DNS_NXDOMAIN->value) {
                return [];
            }

            throw new ResolverException(
                sprintf('DNS lookup for "%s" failed: %s', $hostname, $e->getMessage()),
                0,
                $e
            );
        }

        $records = [];
        foreach ($response->answer as $rr) {
            if (!$rr instanceof TXT) {
                continue;
            }

            // A TXT record is a sequence of character-strings; DMARC treats them
            // as a single value formed by concatenation with no separator.
            $parts = array_map(static fn ($text): string => $text->value(), $rr->text);
            $records[] = implode('', $parts);
        }

        return $records;
    }
}
