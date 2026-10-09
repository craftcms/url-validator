<?php

namespace CraftCms\UrlValidator;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Psr\Http\Message\RequestInterface;

/**
 * Guzzle middleware that validates every request’s URL, including the ones sent when following redirects.
 *
 * Requires `guzzlehttp/guzzle`. A disallowed URL makes the request fail with an [[UrlValidationException]].
 *
 * @author Pixel & Tonic, Inc. <support@pixelandtonic.com>
 */
class GuzzleMiddleware
{
    /**
     * @var string The name the middleware is registered under in a handler stack.
     */
    public const NAME = 'url_validator';

    /**
     * Returns a middleware that validates every request’s URL and pins its hostname to the validated IPs.
     */
    public static function validateRequests(?UrlValidator $validator = null): callable
    {
        $validator = $validator ?? new UrlValidator;

        return static function (callable $handler) use ($validator): callable {
            return static function (RequestInterface $request, array $options) use ($handler, $validator) {
                $url = (string) $request->getUri();

                if (defined('CURLOPT_RESOLVE')) {
                    // Pin the hostname/port to the IPs we just validated.
                    $options['curl'][CURLOPT_RESOLVE] = $validator->curlResolve($url);
                    // with `stream` on, Guzzle uses its stream handler, which ignores curl options and so the pin
                    $options['stream'] = false;
                } else {
                    // the stream handler can’t pin, so only validate
                    $validator->validate($url);
                }

                return $handler($request, $options);
            };
        };
    }

    /**
     * Adds the middleware to the end of the handler stack, so it runs for every redirect hop too.
     */
    public static function push(HandlerStack $handlerStack, ?UrlValidator $validator = null): void
    {
        // pushed to the end of the stack, so it sits below the redirect middleware
        // and gets called for each request sent while following redirects
        $handlerStack->remove(self::NAME);
        $handlerStack->push(self::validateRequests($validator), self::NAME);
    }

    /**
     * Adds the middleware to the client’s handler stack. Returns false if the client doesn’t use one.
     *
     * This relies on `Client::getConfig()`, which is deprecated in Guzzle 7, so prefer [[push()]]
     * when you create the handler stack yourself.
     */
    public static function attach(Client $client, ?UrlValidator $validator = null): bool
    {
        $handlerStack = $client->getConfig('handler');

        if (! $handlerStack instanceof HandlerStack) {
            return false;
        }

        self::push($handlerStack, $validator);

        return true;
    }
}
