<?php

declare(strict_types=1);

/**
 * Production router for PHP's built-in server.
 *
 * Serves the built React app (static files + SPA fallback) and delegates any
 * /api/* request to the JSON front controller. Used in the container as:
 *
 *   php -S 0.0.0.0:$PORT -t public public/router.php
 *
 * In local development the frontend runs under Vite instead, so this router is
 * only exercised in production.
 */

$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// API requests are handled by the JSON front controller.
if (str_starts_with($uri, '/api/')) {
    require __DIR__ . '/index.php';
    return true;
}

$publicDir = __DIR__;
$resolved = realpath($publicDir . $uri);

// Serve an existing static asset (JS, CSS, etc.) directly, but only if it
// resolves to a real file inside the public directory.
if (
    $uri !== '/'
    && $resolved !== false
    && str_starts_with($resolved, $publicDir)
    && is_file($resolved)
) {
    return false; // let the built-in server serve the file with its own MIME handling
}

// SPA fallback: serve the built index.html for all other routes.
$indexHtml = $publicDir . '/index.html';
if (is_file($indexHtml)) {
    header('Content-Type: text/html; charset=UTF-8');
    readfile($indexHtml);
    return true;
}

http_response_code(404);
header('Content-Type: text/plain');
echo "Not found.\n";
return true;
