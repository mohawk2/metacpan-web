package Plack::Middleware::CSPHeaders;
use strict;
use warnings;
use Plack::Util;
use Plack::Builder;

sub new { bless {}, $_[0] }

sub config2headers {
    my ($config) = @_;
    my @csp;
    my @extra_headers;
    for my $key ( sort keys %$config ) {
        my @values = @{ $config->{$key} };
        push @extra_headers,
            'X-Frame-Options' => "SAMEORIGIN"
            if $key eq 'frame_ancestors' and grep /^'self'$/,
            @values;
        $key =~ s#_#-#g;
        push @csp, join ' ', $key, @values;
    }
    ( 'Content-Security-Policy' => join( '; ', @csp ), @extra_headers );
}

sub wrap {
    my ( $self, $app, %config ) = @_;
    my @headers = config2headers( \%config );
    builder {
        sub {
            my ($env) = @_;
            Plack::Util::response_cb( $app->($env),
                sub { push @{ $_[0][1] }, @headers },
            );
        };
    };
}

1;
