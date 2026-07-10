<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Spf;

use Jonathanleist\Dmarcation\LookupQuery;

/**
 * The outcome of discovering and evaluating a domain's SPF record.
 *
 * Unlike DMARC, SPF has no organizational-domain fallback: the record is
 * published as a TXT record at the domain itself, so discovery is a single
 * query. Publishing more than one v=spf1 record is a permerror.
 */
final readonly class SpfLookupResult
{
    /**
     * @param string                    $domain     The domain that was looked up.
     * @param string|null               $record     The SPF record, or null if none/multiple.
     * @param list<LookupQuery>         $queries    Every DNS query performed.
     * @param bool                      $multiple   Whether multiple SPF records were found.
     * @param SpfEvaluationResult|null  $evaluation The recursive lookup evaluation, if a record was found.
     */
    public function __construct(
        public string $domain,
        public ?string $record,
        public array $queries,
        public bool $multiple,
        public ?SpfEvaluationResult $evaluation,
    ) {
    }

    public function found(): bool
    {
        return $this->record !== null;
    }

    /**
     * The records found when more than one SPF record is published.
     *
     * @return list<string>
     */
    public function multipleRecords(): array
    {
        if (!$this->multiple || $this->queries === []) {
            return [];
        }

        return $this->queries[0]->records;
    }
}
