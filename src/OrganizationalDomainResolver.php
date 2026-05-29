<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

/**
 * Determines the organizational (registrable) domain for a given domain.
 *
 * DMARC uses the organizational domain to implement policy inheritance: when a
 * subdomain has no DMARC record of its own, the record published at its
 * organizational domain applies. Identifying that boundary requires knowledge
 * of the Public Suffix List, which is hidden behind this interface so the
 * backing data source can be swapped or faked in tests.
 */
interface OrganizationalDomainResolver
{
    /**
     * Return the organizational domain for $domain (e.g. "example.co.uk" for
     * "mail.example.co.uk"), or null if it cannot be determined or the domain
     * is itself a public suffix.
     */
    public function organizationalDomain(string $domain): ?string;
}
