<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Spf;

/**
 * A single parsed SPF term.
 *
 * A term is either a *mechanism* (all, include, a, mx, ptr, ip4, ip6, exists),
 * optionally prefixed with a qualifier (+, -, ~, ?), or a *modifier* written as
 * name=value (redirect, exp, or an unknown modifier). The "v=spf1" version tag
 * is handled separately by {@see SpfRecord} and is not represented as a term.
 */
final readonly class SpfTerm
{
    /** The mechanism names defined by RFC 7208. */
    public const MECHANISMS = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'];

    /** Mechanisms that trigger a DNS query and count toward the limit of 10. */
    public const LOOKUP_MECHANISMS = ['include', 'a', 'mx', 'ptr', 'exists'];

    /** Human-readable meaning of each qualifier. */
    private const QUALIFIER_LABELS = [
        '+' => 'pass',
        '-' => 'fail',
        '~' => 'softfail',
        '?' => 'neutral',
    ];

    /**
     * @param string      $raw       The term exactly as written (e.g. "-all").
     * @param bool        $isModifier True for name=value modifiers.
     * @param string|null $qualifier '+', '-', '~' or '?' for mechanisms; null
     *                               when absent (defaults to '+') or a modifier.
     * @param string      $name      Mechanism or modifier name, lowercased.
     * @param string|null $value     Everything after the mechanism name
     *                               (including a leading ':' or '/'), or the
     *                               part after '=' for a modifier; null if none.
     */
    public function __construct(
        public string $raw,
        public bool $isModifier,
        public ?string $qualifier,
        public string $name,
        public ?string $value,
    ) {
    }

    public function isMechanism(): bool
    {
        return !$this->isModifier;
    }

    /**
     * Whether this term causes a DNS query and therefore counts toward the
     * RFC 7208 §4.6.4 limit of 10 lookups.
     */
    public function causesLookup(): bool
    {
        if ($this->isModifier) {
            return $this->name === 'redirect';
        }

        return in_array($this->name, self::LOOKUP_MECHANISMS, true);
    }

    /**
     * The effective qualifier for a mechanism (defaulting to '+'), or null for
     * modifiers, which do not take a qualifier.
     */
    public function effectiveQualifier(): ?string
    {
        if ($this->isModifier) {
            return null;
        }

        return $this->qualifier ?? '+';
    }

    /**
     * A short human-readable description of the term, used in the parsed-term
     * listing (e.g. "-all" -> "fail").
     */
    public function describe(): string
    {
        if ($this->isModifier) {
            return 'modifier';
        }

        $qualifier = $this->effectiveQualifier();

        return self::QUALIFIER_LABELS[$qualifier] ?? 'pass';
    }
}
