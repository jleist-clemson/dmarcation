<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

/**
 * The outcome of discovering a domain's DMARC record, including any
 * organizational-domain fallback that was performed.
 */
final readonly class LookupResult
{
    /**
     * @param string            $domain       The domain that was looked up.
     * @param PolicySource      $source       Where the policy came from.
     * @param string|null       $policyDomain The domain that actually published
     *                                        the record (the domain itself when
     *                                        Direct, the organizational domain
     *                                        when inherited, null when none).
     * @param string|null       $record       The DMARC record string, or null.
     * @param list<LookupQuery> $queries      Every DNS query performed, in order.
     */
    public function __construct(
        public string $domain,
        public PolicySource $source,
        public ?string $policyDomain,
        public ?string $record,
        public array $queries,
    ) {
    }

    public function found(): bool
    {
        return $this->record !== null;
    }

    public function isInherited(): bool
    {
        return $this->source === PolicySource::Organizational;
    }

    /**
     * Whether any query returned more than one DMARC record, which RFC 7489
     * treats as an error (the policy must be ignored).
     */
    public function hasMultiple(): bool
    {
        return $this->multipleQuery() !== null;
    }

    /**
     * The query that returned multiple DMARC records, if any.
     */
    public function multipleQuery(): ?LookupQuery
    {
        foreach ($this->queries as $query) {
            if ($query->hasMultiple()) {
                return $query;
            }
        }

        return null;
    }
}
