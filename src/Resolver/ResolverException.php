<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Resolver;

/**
 * Thrown when a DNS lookup cannot be completed (as opposed to completing
 * successfully but finding no records).
 */
final class ResolverException extends \RuntimeException
{
}
