<?php

declare(strict_types=1);

use CraftCms\UrlValidator\UrlValidationException;
use CraftCms\UrlValidator\UrlValidator;

it('returns a CURLOPT_RESOLVE value', function (string $url, array $resolvedIps, string $expected) {
    // Stub DNS resolution so the test never touches the network.
    $validator = new UrlValidator(fn (): array => $resolvedIps);

    expect($validator->curlResolve($url))->toBe([$expected]);
})->with([
    'http default port' => ['http://example.com/a', ['93.184.216.34'], 'example.com:80:93.184.216.34'],
    'https default port' => ['https://example.com/a', ['93.184.216.34'], 'example.com:443:93.184.216.34'],
    'uppercase scheme' => ['HTTPS://example.com/a', ['93.184.216.34'], 'example.com:443:93.184.216.34'],
    'explicit port' => ['https://example.com:8443/a', ['93.184.216.34'], 'example.com:8443:93.184.216.34'],
    'multiple ipv4' => ['https://example.com/a', ['93.184.216.34', '8.8.8.8'], 'example.com:443:93.184.216.34,8.8.8.8'],
    'ipv6 is bracketed' => ['https://example.com/a', ['2606:4700::1'], 'example.com:443:[2606:4700::1]'],
    'ipv4 and ipv6' => ['https://example.com/a', ['1.2.3.4', '2606:4700::1'], 'example.com:443:1.2.3.4,[2606:4700::1]'],
    'host as given' => ['https://Example.COM/a', ['93.184.216.34'], 'Example.COM:443:93.184.216.34'],
]);

it('throws when the URL is disallowed', function (string $url, array $resolvedIps, string $exception) {
    $validator = new UrlValidator(fn (): array => $resolvedIps);

    expect(fn () => $validator->curlResolve($url))
        ->toThrow(UrlValidationException::class, $exception);
})->with([
    'bad scheme' => ['ftp://example.com/a', ['93.184.216.34'], 'contains an invalid scheme'],
    'ip literal' => ['http://10.0.0.1/a', [], 'contains an invalid hostname'],
    'private ip' => ['http://example.com/a', ['10.0.0.1'], 'resolves to an invalid IP address'],
]);

it('resolves the host only once', function () {
    $calls = 0;
    $validator = new UrlValidator(function () use (&$calls): array {
        $calls++;

        return ['93.184.216.34'];
    });

    $validator->curlResolve('https://example.com/a');

    expect($calls)->toBe(1);
});
