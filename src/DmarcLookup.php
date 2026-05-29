<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

use Jonathanleist\Dmarcation\Resolver\DnsResolver;
use Jonathanleist\Dmarcation\Resolver\NetDns2Resolver;

/**
 * Discovers the DMARC record that applies to a domain.
 *
 * Following RFC 7489 §6.6.3, the lookup first queries _dmarc.<domain>. If no
 * record is published there, the policy is inherited from the domain's
 * organizational domain: the lookup then queries _dmarc.<organizational-domain>.
 * This is what makes a subdomain fall back to its parent's policy (and is why
 * the 'sp' tag exists to set a distinct policy for subdomains).
 */
final class DmarcLookup
{
    public function __construct(
        private readonly DnsResolver $resolver = new NetDns2Resolver(),
        private readonly OrganizationalDomainResolver $organizationalDomainResolver = new PdpOrganizationalDomainResolver(),
    ) {
    }

    /**
     * @throws Resolver\ResolverException When a DNS lookup itself fails.
     */
    public function forDomain(string $domain): LookupResult
    {
        $domain = $this->normalizeDomain($domain);
        $queries = [];

        // Step 1: the domain's own record.
        $direct = $this->queryDmarc($domain);
        $queries[] = $direct;

        if ($direct->hasMultiple()) {
            return new LookupResult($domain, PolicySource::None, null, null, $queries);
        }

        if ($direct->isUnique()) {
            return new LookupResult($domain, PolicySource::Direct, $domain, $direct->record(), $queries);
        }

        // Step 2: fall back to the organizational domain, if the domain is a
        // subdomain of one.
        $organizationalDomain = $this->organizationalDomainResolver->organizationalDomain($domain);
        if ($organizationalDomain === null || $organizationalDomain === $domain) {
            return new LookupResult($domain, PolicySource::None, null, null, $queries);
        }

        $inherited = $this->queryDmarc($organizationalDomain);
        $queries[] = $inherited;

        if ($inherited->isUnique()) {
            return new LookupResult(
                $domain,
                PolicySource::Organizational,
                $organizationalDomain,
                $inherited->record(),
                $queries
            );
        }

        return new LookupResult($domain, PolicySource::None, null, null, $queries);
    }

    private function queryDmarc(string $domain): LookupQuery
    {
        $name = '_dmarc.' . $domain;
        $txtRecords = $this->resolver->txtRecords($name);

        $dmarcRecords = array_values(
            array_filter($txtRecords, $this->looksLikeDmarc(...))
        );

        return new LookupQuery($name, $dmarcRecords);
    }

    private function normalizeDomain(string $domain): string
    {
        $domain = strtolower(trim($domain));
        $domain = rtrim($domain, '.');

        // Allow callers to pass either "example.com" or "_dmarc.example.com".
        if (str_starts_with($domain, '_dmarc.')) {
            $domain = substr($domain, strlen('_dmarc.'));
        }

        return $domain;
    }

    /**
     * Per RFC 7489, records that do not start with "v=DMARC1" are not DMARC
     * records and must be ignored during discovery.
     */
    private function looksLikeDmarc(string $record): bool
    {
        return preg_match('/^\s*v\s*=\s*DMARC1\s*(;|$)/i', $record) === 1;
    }
}
