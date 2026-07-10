<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Spf;

/**
 * A single node in the tree of SPF records visited while following include: and
 * redirect= references. The root node is the domain being evaluated; every
 * other node was reached through an include or redirect.
 */
final readonly class SpfEvaluationNode
{
    /**
     * @param string                   $via           How this record was reached:
     *                                                 'root', 'include' or 'redirect'.
     * @param string                   $domain        The domain whose record this is.
     * @param string|null              $record        The SPF record found, or null.
     * @param int                      $directLookups Lookup-causing terms in this
     *                                                 record alone (not its children).
     * @param list<SpfEvaluationNode>  $children      Nodes for each include/redirect.
     * @param string|null              $note          A reason this branch ended
     *                                                 early (no record, loop, etc.).
     */
    public function __construct(
        public string $via,
        public string $domain,
        public ?string $record,
        public int $directLookups,
        public array $children,
        public ?string $note,
    ) {
    }
}
