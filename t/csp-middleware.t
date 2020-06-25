use strict;
use warnings;

use Test::More;
use Plack::Middleware::CSPHeaders;

my @got = Plack::Middleware::CSPHeaders::config2headers( {
    default_src => [qw(* 'unsafe-inline')],
    script_src =>
        [qw('self' 'unsafe-inline' *.metacpan.org *.google-analytics.com)],
} );
is_deeply \@got,
    [ 'Content-Security-Policy' =>
        "default-src * 'unsafe-inline'; script-src 'self' 'unsafe-inline' *.metacpan.org *.google-analytics.com",
    ], "normal config" or diag explain \@got;

@got = Plack::Middleware::CSPHeaders::config2headers( {
    default_src => [qw(* 'unsafe-inline')],
    script_src =>
        [qw('self' 'unsafe-inline' *.metacpan.org *.google-analytics.com)],
    frame_ancestors => [qw('self' *.metacpan.org)],
} );
is_deeply \@got,
    [
    'Content-Security-Policy' =>
        "default-src * 'unsafe-inline'; frame-ancestors 'self' *.metacpan.org; script-src 'self' 'unsafe-inline' *.metacpan.org *.google-analytics.com",
    'X-Frame-Options' => "SAMEORIGIN",
    ],
    "with frame-ancestors 'self'"
    or diag explain \@got;

done_testing;
