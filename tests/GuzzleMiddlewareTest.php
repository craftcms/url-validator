<?php

declare(strict_types=1);

use CraftCms\UrlValidator\GuzzleMiddleware;
use CraftCms\UrlValidator\UrlValidationException;
use CraftCms\UrlValidator\UrlValidator;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

/**
 * Builds a client whose handler records each request (and the options it was sent with)
 * before returning the queued responses.
 *
 * @param  Response[]  $responses
 * @param  array<int, array{url:string, options:array<string, mixed>}>  $log
 */
function recordingClient(array $responses, UrlValidator $validator, array &$log): Client
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create(function (RequestInterface $request, array $options) use ($mock, &$log) {
        $log[] = ['url' => (string) $request->getUri(), 'options' => $options];

        return $mock($request, $options);
    });
    GuzzleMiddleware::push($stack, $validator);

    return new Client(['handler' => $stack]);
}

/**
 * Builds a validator that resolves hosts from the given map, and counts the lookups.
 *
 * @param  array<string, string[]>  $dns
 * @param  string[]  $allowedPrivateHosts
 */
function mappedValidator(array $dns, array $allowedPrivateHosts = [], ?int &$lookups = null): UrlValidator
{
    $lookups = 0;

    return new UrlValidator(function (string $host) use ($dns, &$lookups): array {
        $lookups++;

        return $dns[$host] ?? [];
    }, ['allowedPrivateHosts' => $allowedPrivateHosts]);
}

/**
 * Returns the CURLOPT_RESOLVE value each recorded request was sent with.
 *
 * @param  array<int, array{url:string, options:array<string, mixed>}>  $log
 * @return array<int, mixed>
 */
function pins(array $log): array
{
    return array_map(fn (array $entry) => $entry['options']['curl'][CURLOPT_RESOLVE] ?? null, $log);
}

$dns = [
    'example.com' => ['93.184.216.34'],
    'other.example' => ['8.8.8.8'],
    'evil.example' => ['10.0.0.5'],
    'api.internal' => ['10.0.0.6'],
];

it('pins the first request', function () use ($dns) {
    $log = [];
    $response = recordingClient([new Response(200)], mappedValidator($dns), $log)->get('https://example.com/a');

    expect($response->getStatusCode())->toBe(200)
        ->and(pins($log))->toBe([['example.com:443:93.184.216.34']]);
});

it('validates and pins every redirect', function () use ($dns) {
    $log = [];
    $client = recordingClient([
        new Response(302, ['Location' => '/b']),
        new Response(301, ['Location' => 'http://other.example:8080/c']),
        new Response(200),
    ], mappedValidator($dns), $log);

    expect($client->get('https://example.com/a')->getStatusCode())->toBe(200)
        ->and(array_column($log, 'url'))->toBe(['https://example.com/a', 'https://example.com/b', 'http://other.example:8080/c'])
        ->and(pins($log))->toBe([
            ['example.com:443:93.184.216.34'],
            ['example.com:443:93.184.216.34'],
            ['other.example:8080:8.8.8.8'],
        ]);
});

it('blocks disallowed redirect targets before they are requested', function (string $location, string $exception) use ($dns) {
    $log = [];
    $client = recordingClient([
        new Response(302, ['Location' => $location]),
        new Response(200),
    ], mappedValidator($dns), $log);

    expect(fn () => $client->get('https://example.com/a'))
        ->toThrow(UrlValidationException::class, $exception)
        ->and(array_column($log, 'url'))->toBe(['https://example.com/a']);
})->with([
    'host resolving to a private ip' => ['http://evil.example/', 'resolves to an invalid IP address'],
    'ip literal' => ['http://169.254.169.254/latest/meta-data/', 'contains an invalid hostname'],
    'metadata domain' => ['http://metadata.google.internal/', 'contains an invalid hostname'],
]);

it('follows redirects to allowlisted internal hosts', function () use ($dns) {
    $log = [];
    $client = recordingClient([
        new Response(302, ['Location' => 'http://api.internal/x']),
        new Response(200),
    ], mappedValidator($dns, ['api.internal']), $log);

    expect($client->get('https://example.com/a')->getStatusCode())->toBe(200)
        ->and(pins($log)[1])->toBe(['api.internal:80:10.0.0.6']);
});

it('turns the stream option off', function () use ($dns) {
    $log = [];
    recordingClient([new Response(200)], mappedValidator($dns), $log)->get('https://example.com/a', ['stream' => true]);

    expect($log[0]['options']['stream'])->toBeFalse();
});

it('respects allow_redirects being off', function () use ($dns) {
    $log = [];
    $client = recordingClient([
        new Response(302, ['Location' => 'http://evil.example/']),
        new Response(200),
    ], mappedValidator($dns), $log);

    expect($client->get('https://example.com/a', ['allow_redirects' => false])->getStatusCode())->toBe(302)
        ->and($log)->toHaveCount(1);
});

it('only adds the middleware once', function () use ($dns) {
    $log = [];
    $validator = mappedValidator($dns, [], $lookups);
    $mock = new MockHandler([new Response(302, ['Location' => '/b']), new Response(200)]);
    $stack = HandlerStack::create($mock);
    GuzzleMiddleware::push($stack, $validator);
    GuzzleMiddleware::push($stack, $validator);

    (new Client(['handler' => $stack]))->get('https://example.com/a');

    // one lookup per hop
    expect($lookups)->toBe(2);
});

it('attaches to clients with a handler stack', function () use ($dns) {
    $validator = mappedValidator($dns);

    expect(GuzzleMiddleware::attach(new Client(['handler' => HandlerStack::create(new MockHandler)]), $validator))->toBeTrue()
        ->and(GuzzleMiddleware::attach(new Client(['handler' => fn () => null]), $validator))->toBeFalse();
});

it('uses a default validator', function () {
    $stack = HandlerStack::create(new MockHandler([new Response(200)]));
    $stack->push(GuzzleMiddleware::validateRequests());

    // an IP literal is rejected before any DNS lookup happens
    expect(fn () => (new Client(['handler' => $stack]))->get('http://127.0.0.1/'))
        ->toThrow(UrlValidationException::class, 'contains an invalid hostname');
});
