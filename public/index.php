<?php

declare(strict_types=1);

/**
 * Minimal JSON HTTP API exposing the dmarcation library to the web front-end.
 *
 * Routes:
 *   POST /api/validate   body: { "record": "<dmarc record>" }
 *   GET  /api/lookup     query: ?domain=<domain>[&ns=<nameserver>]
 *
 * Run with PHP's built-in server:
 *   php -S localhost:8000 -t public
 */

use Jonathanleist\Dmarcation\DmarcLookup;
use Jonathanleist\Dmarcation\DmarcRecord;
use Jonathanleist\Dmarcation\LookupResult;
use Jonathanleist\Dmarcation\Resolver\NetDns2Resolver;
use Jonathanleist\Dmarcation\Resolver\ResolverException;
use Jonathanleist\Dmarcation\ValidationResult;

require __DIR__ . '/../vendor/autoload.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

/**
 * @param array<string, mixed> $data
 */
function send_json(array $data, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Serialize a ValidationResult into a JSON-friendly array.
 *
 * @return array<string, mixed>
 */
function serialize_validation(ValidationResult $result): array
{
    $issues = [];
    foreach ($result->getIssues() as $issue) {
        $issues[] = [
            'severity' => $issue->severity->value,
            'tag' => $issue->tag,
            'message' => $issue->message,
        ];
    }

    return [
        'valid' => $result->isValid(),
        'tags' => $result->getTags(),
        'issues' => $issues,
        'errorCount' => count($result->getErrors()),
        'warningCount' => count($result->getWarnings()),
    ];
}

/**
 * @return array<string, mixed>
 */
function serialize_lookup(LookupResult $result): array
{
    $queries = [];
    foreach ($result->queries as $query) {
        $queries[] = [
            'name' => $query->name,
            'count' => count($query->records),
            'records' => $query->records,
        ];
    }

    $effectivePolicy = null;
    if ($result->isInherited() && $result->record !== null) {
        $tags = DmarcRecord::fromString($result->record)->getTags();
        if (isset($tags['sp'])) {
            $effectivePolicy = ['policy' => $tags['sp'], 'via' => 'sp'];
        } elseif (isset($tags['p'])) {
            $effectivePolicy = ['policy' => $tags['p'], 'via' => 'p'];
        }
    }

    $multiple = $result->multipleQuery();

    return [
        'domain' => $result->domain,
        'source' => $result->source->value,
        'policyDomain' => $result->policyDomain,
        'record' => $result->record,
        'found' => $result->found(),
        'inherited' => $result->isInherited(),
        'multiple' => $multiple !== null,
        'multipleQuery' => $multiple !== null
            ? ['name' => $multiple->name, 'records' => $multiple->records]
            : null,
        'effectivePolicy' => $effectivePolicy,
        'queries' => $queries,
        'validation' => $result->record !== null
            ? serialize_validation(DmarcRecord::fromString($result->record)->validate())
            : null,
    ];
}

$path = rtrim(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/', '/');
$method = $_SERVER['REQUEST_METHOD'];

if ($path === '/api/validate' && in_array($method, ['POST', 'GET'], true)) {
    if ($method === 'POST') {
        $body = json_decode(file_get_contents('php://input') ?: '', true);
        $record = is_array($body) ? ($body['record'] ?? null) : null;
    } else {
        $record = $_GET['record'] ?? null;
    }

    if (!is_string($record) || trim($record) === '') {
        send_json(['error' => 'A non-empty "record" is required.'], 400);
    }

    send_json([
        'record' => $record,
        'validation' => serialize_validation(DmarcRecord::fromString($record)->validate()),
    ]);
}

if ($path === '/api/lookup' && $method === 'GET') {
    $domain = $_GET['domain'] ?? null;
    if (!is_string($domain) || trim($domain) === '') {
        send_json(['error' => 'A non-empty "domain" is required.'], 400);
    }

    $ns = $_GET['ns'] ?? null;
    $nameservers = is_string($ns) && trim($ns) !== '' ? [trim($ns)] : [];

    $lookup = new DmarcLookup(new NetDns2Resolver($nameservers));

    try {
        $result = $lookup->forDomain($domain);
    } catch (ResolverException $e) {
        send_json(['error' => $e->getMessage()], 502);
    }

    send_json(serialize_lookup($result));
}

send_json(['error' => 'Not found.'], 404);
