<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Spf;

use Jonathanleist\Dmarcation\LookupQuery;
use Jonathanleist\Dmarcation\Resolver\DnsResolver;
use Jonathanleist\Dmarcation\Resolver\NetDns2Resolver;

/**
 * Discovers the SPF record published at a domain and, when exactly one is
 * found, recursively evaluates its include/redirect tree via {@see SpfEvaluator}.
 */
final class SpfLookup
{
    private readonly SpfEvaluator $evaluator;

    public function __construct(
        private readonly DnsResolver $resolver = new NetDns2Resolver(),
    ) {
        $this->evaluator = new SpfEvaluator($this->resolver);
    }

    /**
     * @throws \Jonathanleist\Dmarcation\Resolver\ResolverException When a DNS lookup itself fails.
     */
    public function forDomain(string $domain): SpfLookupResult
    {
        $domain = $this->normalize($domain);
        $records = $this->querySpf($domain);
        $queries = [new LookupQuery($domain, $records)];

        if (count($records) > 1) {
            return new SpfLookupResult($domain, null, $queries, true, null);
        }

        if ($records === []) {
            return new SpfLookupResult($domain, null, $queries, false, null);
        }

        $evaluation = $this->evaluator->evaluate($domain, $records);

        return new SpfLookupResult($domain, $records[0], $queries, false, $evaluation);
    }

    /**
     * @return list<string>
     */
    private function querySpf(string $domain): array
    {
        $txt = $this->resolver->txtRecords($domain);

        return array_values(array_filter(
            $txt,
            static fn (string $record): bool => preg_match('/^\s*v=spf1(\s|$)/i', $record) === 1
        ));
    }

    private function normalize(string $domain): string
    {
        return rtrim(strtolower(trim($domain)), '.');
    }
}
