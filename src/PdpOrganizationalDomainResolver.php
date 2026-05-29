<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

use Pdp\Rules;

/**
 * An {@see OrganizationalDomainResolver} backed by jeremykendall/php-domain-parser
 * and a bundled snapshot of the Public Suffix List.
 */
final class PdpOrganizationalDomainResolver implements OrganizationalDomainResolver
{
    private const DEFAULT_PSL = __DIR__ . '/../resources/public_suffix_list.dat';

    private Rules $rules;

    /**
     * @param string|null $publicSuffixListPath Path to a Public Suffix List
     *                                          file; defaults to the bundled
     *                                          snapshot.
     */
    public function __construct(?string $publicSuffixListPath = null)
    {
        $this->rules = Rules::fromPath($publicSuffixListPath ?? self::DEFAULT_PSL);
    }

    public function organizationalDomain(string $domain): ?string
    {
        return $this->rules->resolve($domain)->registrableDomain()->value();
    }
}
