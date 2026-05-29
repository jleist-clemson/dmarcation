<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

/**
 * Severity of a single validation issue.
 *
 * An "error" means the record violates the DMARC specification and will likely
 * be rejected or ignored by receivers. A "warning" means the record is
 * technically usable but contains something questionable or non-recommended.
 */
enum Severity: string
{
    case Error = 'error';
    case Warning = 'warning';
}
