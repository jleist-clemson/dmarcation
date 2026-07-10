<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Spf;

use Jonathanleist\Dmarcation\Resolver\DnsResolver;
use Jonathanleist\Dmarcation\Resolver\NetDns2Resolver;
use Jonathanleist\Dmarcation\Severity;
use Jonathanleist\Dmarcation\ValidationIssue;

/**
 * Recursively evaluates a domain's SPF record, following include: mechanisms and
 * the redirect= modifier, to count the DNS lookups the record actually requires.
 *
 * RFC 7208 §4.6.4 caps this at 10 DNS-querying terms (include, a, mx, ptr,
 * exists, redirect) across the whole tree, and at 2 "void" lookups (queries that
 * return no usable answer). Exceeding either limit is a permerror in practice,
 * so this is the single most valuable check a real-world SPF validator performs.
 */
final class SpfEvaluator
{
    public const LOOKUP_LIMIT = SpfRecord::LOOKUP_LIMIT;
    public const VOID_LIMIT = 2;

    /**
     * A hard ceiling on DNS queries so a large (but acyclic) include tree cannot
     * make us issue an unbounded number of lookups. Well above the 10-lookup
     * limit so realistic over-limit records are still reported accurately.
     */
    private const MAX_FETCHES = 50;

    public function __construct(
        private readonly DnsResolver $resolver = new NetDns2Resolver(),
    ) {
    }

    /**
     * @param list<string>|null $knownRecords The root domain's SPF record(s) if
     *                                        already fetched, to avoid a redundant
     *                                        query; otherwise they are looked up.
     *
     * @throws \Jonathanleist\Dmarcation\Resolver\ResolverException
     */
    public function evaluate(string $domain, ?array $knownRecords = null): SpfEvaluationResult
    {
        $context = ['lookups' => 0, 'voids' => 0, 'fetches' => 0, 'issues' => [], 'stopped' => false];

        $root = $this->resolveNode('root', $this->normalize($domain), [], $context, $knownRecords);

        return new SpfEvaluationResult(
            $context['lookups'],
            self::LOOKUP_LIMIT,
            $context['voids'],
            self::VOID_LIMIT,
            $root,
            $context['issues'],
        );
    }

    /**
     * @param list<string>              $ancestors The chain of domains from the
     *                                             root to this node's parent, used
     *                                             to detect include/redirect loops.
     * @param array<string, mixed>      $context   Mutable running totals.
     * @param list<string>|null         $known     Pre-fetched records for this node.
     */
    private function resolveNode(string $via, string $domain, array $ancestors, array &$context, ?array $known = null): SpfEvaluationNode
    {
        if ($context['fetches'] >= self::MAX_FETCHES) {
            $this->flagOnce($context, 'stopped', Severity::Error, 'Evaluation stopped: too many DNS lookups.');

            return new SpfEvaluationNode($via, $domain, null, 0, [], 'not expanded (lookup budget exhausted)');
        }

        $records = $known ?? $this->querySpf($domain);
        if ($known === null) {
            $context['fetches']++;
        }

        if (count($records) > 1) {
            $context['issues'][] = new ValidationIssue(
                Severity::Error,
                sprintf("'%s' publishes multiple SPF records; exactly one is allowed (permerror).", $domain)
            );

            return new SpfEvaluationNode($via, $domain, null, 0, [], 'multiple SPF records');
        }

        if ($records === []) {
            // A missing record at an include/redirect target is a void lookup and
            // a permerror; at the root it just means the domain has no policy.
            if ($via !== 'root') {
                $context['voids']++;
                $context['issues'][] = new ValidationIssue(
                    Severity::Error,
                    sprintf("'%s' (reached via %s) has no SPF record; this causes a permerror.", $domain, $via)
                );
            }

            return new SpfEvaluationNode($via, $domain, null, 0, [], 'no SPF record found');
        }

        $record = $records[0];
        $parsed = SpfRecord::fromString($record);

        $followRedirect = !$this->hasAllMechanism($parsed);
        $directLookups = $this->countActiveLookups($parsed, $followRedirect);
        $context['lookups'] += $directLookups;

        $children = [];
        foreach ($this->recursionTargets($parsed, $followRedirect) as [$childVia, $target]) {
            if (str_contains($target, '%')) {
                $children[] = new SpfEvaluationNode($childVia, $target, null, 0, [], 'contains a macro; not expanded');
                continue;
            }

            $normalized = $this->normalize($target);
            if (in_array($normalized, [...$ancestors, $domain], true)) {
                $context['issues'][] = new ValidationIssue(
                    Severity::Error,
                    sprintf("Include/redirect loop detected at '%s'.", $normalized)
                );
                $children[] = new SpfEvaluationNode($childVia, $normalized, null, 0, [], 'loop detected');
                continue;
            }

            $children[] = $this->resolveNode($childVia, $normalized, [...$ancestors, $domain], $context);
        }

        return new SpfEvaluationNode($via, $domain, $record, $directLookups, $children, null);
    }

    /**
     * Count the lookup-causing terms that would actually be evaluated: every
     * include/a/mx/ptr/exists, plus redirect only when it is not shadowed by an
     * 'all' mechanism.
     */
    private function countActiveLookups(SpfRecord $record, bool $followRedirect): int
    {
        $count = 0;
        foreach ($record->getTerms() as $term) {
            if (!$term->causesLookup()) {
                continue;
            }
            if ($term->isModifier && $term->name === 'redirect' && !$followRedirect) {
                continue;
            }
            $count++;
        }

        return $count;
    }

    /**
     * The include and redirect targets to recurse into, as [via, domain] pairs.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function recursionTargets(SpfRecord $record, bool $followRedirect): array
    {
        $targets = [];
        foreach ($record->getTerms() as $term) {
            if ($term->isMechanism() && $term->name === 'include' && $term->value !== null && str_starts_with($term->value, ':')) {
                $domain = substr($term->value, 1);
                if ($domain !== '') {
                    $targets[] = ['include', $domain];
                }
            }

            if ($followRedirect && $term->isModifier && $term->name === 'redirect' && (string) $term->value !== '') {
                $targets[] = ['redirect', (string) $term->value];
            }
        }

        return $targets;
    }

    private function hasAllMechanism(SpfRecord $record): bool
    {
        foreach ($record->getTerms() as $term) {
            if ($term->isMechanism() && $term->name === 'all') {
                return true;
            }
        }

        return false;
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

    /**
     * @param array<string, mixed> $context
     */
    private function flagOnce(array &$context, string $key, Severity $severity, string $message): void
    {
        if ($context[$key] === true) {
            return;
        }
        $context[$key] = true;
        $context['issues'][] = new ValidationIssue($severity, $message);
    }

    private function normalize(string $domain): string
    {
        return rtrim(strtolower(trim($domain)), '.');
    }
}
