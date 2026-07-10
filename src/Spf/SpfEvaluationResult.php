<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Spf;

use Jonathanleist\Dmarcation\ValidationIssue;

/**
 * The outcome of recursively evaluating a domain's SPF record: how many DNS
 * lookups the full include/redirect tree requires, measured against the
 * RFC 7208 §4.6.4 limits, plus the tree itself and any problems found along the
 * way (over-limit, include loops, targets with no SPF record).
 */
final readonly class SpfEvaluationResult
{
    /**
     * @param int                  $lookupCount Total DNS-querying terms across the tree.
     * @param int                  $lookupLimit The limit (10).
     * @param int                  $voidCount   DNS lookups that returned no usable record.
     * @param int                  $voidLimit   The void-lookup limit (2).
     * @param SpfEvaluationNode    $root        Root of the evaluated tree.
     * @param list<ValidationIssue> $issues     Problems found during evaluation.
     */
    public function __construct(
        public int $lookupCount,
        public int $lookupLimit,
        public int $voidCount,
        public int $voidLimit,
        public SpfEvaluationNode $root,
        public array $issues,
    ) {
    }

    public function withinLookupLimit(): bool
    {
        return $this->lookupCount <= $this->lookupLimit;
    }

    public function withinVoidLimit(): bool
    {
        return $this->voidCount <= $this->voidLimit;
    }
}
