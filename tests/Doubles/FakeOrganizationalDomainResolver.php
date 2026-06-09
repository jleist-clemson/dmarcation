<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Tests\Doubles;

use Jonathanleist\Dmarcation\OrganizationalDomainResolver;

/**
 * Maps domains to organizational domains from a fixed table, so lookup tests
 * don't depend on the bundled Public Suffix List.
 */
final class FakeOrganizationalDomainResolver implements OrganizationalDomainResolver
{
    /**
     * @param array<string, string|null> $map domain => organizational domain
     */
    public function __construct(private readonly array $map = [])
    {
    }

    public function organizationalDomain(string $domain): ?string
    {
        return $this->map[$domain] ?? null;
    }
}
