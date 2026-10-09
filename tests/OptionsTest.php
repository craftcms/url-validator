<?php

declare(strict_types=1);

use CraftCms\UrlValidator\UrlValidationException;
use CraftCms\UrlValidator\UrlValidator;

it('can allow other schemes', function () {
    $validator = new UrlValidator(fn (): array => ['93.184.216.34'], ['allowedSchemes' => ['http', 'https', 'ftp']]);

    expect($validator->validate('ftp://example.com/a'))->toBe(['93.184.216.34']);
});

it('can disallow other hostnames', function () {
    $validator = new UrlValidator(fn (): array => ['93.184.216.34'], ['disallowedHostnames' => ['blocked.example.com']]);

    expect(fn () => $validator->validate('https://blocked.example.com/a'))
        ->toThrow(UrlValidationException::class, 'contains an invalid hostname');
});

it('can disallow other IPv4 addresses', function () {
    $validator = new UrlValidator(fn (): array => ['93.184.216.34'], ['disallowedIpv4Addresses' => ['93.184.216.34']]);

    expect(fn () => $validator->validate('https://example.com/a'))
        ->toThrow(UrlValidationException::class, 'resolves to an invalid IP address');
});

it('can disallow other IPv4 ranges', function () {
    $validator = new UrlValidator(fn (): array => ['93.184.216.34'], ['disallowedIpv4Ranges' => [['93.184.0.0', 16]]]);

    expect(fn () => $validator->validate('https://example.com/a'))
        ->toThrow(UrlValidationException::class, 'resolves to an invalid IP address');
});

it('can disallow other IPv6 addresses', function () {
    $validator = new UrlValidator(fn (): array => ['2606:4700::1'], ['disallowedIpv6Addresses' => ['2606:4700:0::1']]);

    expect(fn () => $validator->validate('https://example.com/a'))
        ->toThrow(UrlValidationException::class, 'resolves to an invalid IP address');
});

it('can change the IPv4 filter flags', function () {
    $validator = new UrlValidator(options: ['ipv4FilterFlags' => FILTER_FLAG_NO_RES_RANGE]);

    expect($validator->validateIp('10.0.0.1'))->toBeTrue()
        ->and($validator->validateIp('127.0.0.1'))->toBeFalse();
});

it('always adds the IP version flag to custom filter flags', function () {
    $validator = new UrlValidator(options: ['ipv4FilterFlags' => FILTER_FLAG_NO_RES_RANGE, 'ipv6FilterFlags' => FILTER_FLAG_NO_RES_RANGE]);

    // an IPv6 address mustn’t pass the IPv4 check, and vice versa
    $method = new ReflectionMethod(UrlValidator::class, 'validateIpv4');

    expect($method->invoke($validator, '2606:4700::1', false))->toBeFalse()
        ->and($validator->validateIp('fd12::1'))->toBeTrue();
});
