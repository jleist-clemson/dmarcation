<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

/**
 * Describes where a domain's effective DMARC policy came from.
 */
enum PolicySource: string
{
    /** A DMARC record is published at the queried domain itself. */
    case Direct = 'direct';

    /** No record at the domain; inherited from its organizational domain. */
    case Organizational = 'organizational';

    /** No applicable DMARC record was found. */
    case None = 'none';
}
