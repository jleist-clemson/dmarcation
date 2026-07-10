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
use Jonathanleist\Dmarcation\Spf\SpfEvaluationNode;
use Jonathanleist\Dmarcation\Spf\SpfEvaluationResult;
use Jonathanleist\Dmarcation\Spf\SpfLookup;
use Jonathanleist\Dmarcation\Spf\SpfLookupResult;
use Jonathanleist\Dmarcation\Spf\SpfRecord;
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
 * Serialize a list of ValidationIssue objects into JSON-friendly arrays.
 *
 * @param iterable<\Jonathanleist\Dmarcation\ValidationIssue> $issues
 *
 * @return list<array<string, mixed>>
 */
function serialize_issues(iterable $issues): array
{
    $out = [];
    foreach ($issues as $issue) {
        $out[] = [
            'severity' => $issue->severity->value,
            'tag' => $issue->tag,
            'message' => $issue->message,
        ];
    }

    return $out;
}

/**
 * Serialize a ValidationResult into a JSON-friendly array.
 *
 * @return array<string, mixed>
 */
function serialize_validation(ValidationResult $result): array
{
    return [
        'valid' => $result->isValid(),
        'tags' => $result->getTags(),
        'issues' => serialize_issues($result->getIssues()),
        'errorCount' => count($result->getErrors()),
        'warningCount' => count($result->getWarnings()),
    ];
}

/**
 * Serialize an SpfRecord's syntax validation, including its parsed terms.
 *
 * @return array<string, mixed>
 */
function serialize_spf_validation(SpfRecord $record): array
{
    $result = $record->validate();

    $terms = [];
    foreach ($record->getTerms() as $term) {
        $terms[] = [
            'raw' => $term->raw,
            'kind' => $term->isModifier ? 'modifier' : 'mechanism',
            'qualifier' => $term->effectiveQualifier(),
            'name' => $term->name,
            'value' => $term->value,
            'description' => $term->describe(),
            'causesLookup' => $term->causesLookup(),
        ];
    }

    return [
        'valid' => $result->isValid(),
        'version' => $record->getVersion(),
        'terms' => $terms,
        'issues' => serialize_issues($result->getIssues()),
        'errorCount' => count($result->getErrors()),
        'warningCount' => count($result->getWarnings()),
        'lookupTerms' => $record->countLookupTerms(),
    ];
}

/**
 * Serialize a node of the SPF include/redirect tree, recursively.
 *
 * @return array<string, mixed>
 */
function serialize_spf_node(SpfEvaluationNode $node): array
{
    return [
        'via' => $node->via,
        'domain' => $node->domain,
        'record' => $node->record,
        'directLookups' => $node->directLookups,
        'note' => $node->note,
        'children' => array_map('serialize_spf_node', $node->children),
    ];
}

/**
 * Serialize the recursive SPF lookup evaluation.
 *
 * @return array<string, mixed>
 */
function serialize_spf_evaluation(SpfEvaluationResult $evaluation): array
{
    return [
        'lookupCount' => $evaluation->lookupCount,
        'lookupLimit' => $evaluation->lookupLimit,
        'voidCount' => $evaluation->voidCount,
        'voidLimit' => $evaluation->voidLimit,
        'withinLimit' => $evaluation->withinLookupLimit(),
        'withinVoidLimit' => $evaluation->withinVoidLimit(),
        'tree' => serialize_spf_node($evaluation->root),
        'issues' => serialize_issues($evaluation->issues),
    ];
}

/**
 * @return array<string, mixed>
 */
function serialize_spf_lookup(SpfLookupResult $result): array
{
    $queries = [];
    foreach ($result->queries as $query) {
        $queries[] = [
            'name' => $query->name,
            'count' => count($query->records),
            'records' => $query->records,
        ];
    }

    return [
        'domain' => $result->domain,
        'record' => $result->record,
        'found' => $result->found(),
        'multiple' => $result->multiple,
        'multipleRecords' => $result->multipleRecords(),
        'queries' => $queries,
        'validation' => $result->record !== null
            ? serialize_spf_validation(SpfRecord::fromString($result->record))
            : null,
        'evaluation' => $result->evaluation !== null
            ? serialize_spf_evaluation($result->evaluation)
            : null,
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

if ($path === '/api/health') {
    send_json(['status' => 'ok']);
}

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

if ($path === '/api/spf/validate' && in_array($method, ['POST', 'GET'], true)) {
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
        'validation' => serialize_spf_validation(SpfRecord::fromString($record)),
    ]);
}

if ($path === '/api/spf/lookup' && $method === 'GET') {
    $domain = $_GET['domain'] ?? null;
    if (!is_string($domain) || trim($domain) === '') {
        send_json(['error' => 'A non-empty "domain" is required.'], 400);
    }

    $ns = $_GET['ns'] ?? null;
    $nameservers = is_string($ns) && trim($ns) !== '' ? [trim($ns)] : [];

    $lookup = new SpfLookup(new NetDns2Resolver($nameservers));

    try {
        $result = $lookup->forDomain($domain);
    } catch (ResolverException $e) {
        send_json(['error' => $e->getMessage()], 502);
    }

    send_json(serialize_spf_lookup($result));
}

send_json(['error' => 'Not found.'], 404);
