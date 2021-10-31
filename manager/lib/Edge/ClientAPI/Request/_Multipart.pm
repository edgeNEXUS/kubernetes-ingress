# Based on <https://metacpan.org/pod/HTTP::Tiny::Multipart>
package Edge::ClientAPI::Request::_Multipart;
use common::sense;
use AnyEvent 5.0  ();
use AnyEvent::Log ();
use AnyEvent::HTTP;

use File::Basename;
use Carp;
use MIME::Base64;

sub _get_boundary {
    my ($headers, $content) = @_;

    # Generate and check boundary
    my $boundary;
    my $size = 1;

    while (1) {
        $boundary = encode_base64 join('', map chr(rand 256), 1 .. $size++ * 3);
        $boundary =~ s/\W/X/g;
        last unless grep{ $_ =~ m{$boundary} }@{$content};
    }

    # Add boundary to Content-Type header
    my $before = 'multipart/form-data';
    my $after  = '';
    if( defined $headers->{'content-type'} ) {
        if( $headers->{'content-type'} =~ m!^(.*multipart/[^;]+)(.*)$! ) {
            $before = $1;
            $after  = $2;
        }
    }

    $headers->{'content-type'} = "$before; boundary=$boundary$after";

    return "--$boundary\x0d\x0a";
}

sub _build_content {
    my ($data, $parameters) = @_;

    my @params = ref $data eq 'HASH' ? %$data : @$data;
    @params % 2 == 0
        or Carp::croak("form data reference must have an even number of terms\n");

    my @params2 = ref $parameters eq 'HASH' ? %$parameters : @$parameters;
    while (@params2) {
        my ($key, $value) = splice(@params2, 0, 2);
        push @params, $key => [ $value ];
    }
    undef @params2;

    my @terms;
    while( @params ) {
        my ($key, $value) = splice(@params, 0, 2);
        if ( ref $value eq 'ARRAY' ) {
            unshift @params, map { $key => $_ } @$value;
        }
        else {
            my $filename     = '';
            my $content      = $value;
            my $content_type = '';

            if ( ref $value and ref $value eq 'HASH' ) {
                if ( $value->{content} ) {
                    $content = $value->{content};
                }

                if ( $value->{filename} ) {
                    $filename = $value->{filename};
                    $filename = '; filename="' . basename( $filename ) . '"';
                }

                if ( $value->{content_type} ) {
                    $content_type = "\x0d\x0aContent-Type: " . $value->{content_type};
                }
            }

            push @terms, sprintf "Content-Disposition: form-data; name=\"%s\"%s%s\x0d\x0a\x0d\x0a%s\x0d\x0a",
                $key,
                $filename,
                $content_type,
                $content;
        }
    }

    return \@terms;
}

sub body($$$) {
    my ($data, $parameters, $headers) = @_;
    my $content_parts = _build_content($data, $parameters);
    my $boundary      = _get_boundary($headers, $content_parts);

    my $last_boundary = $boundary;
    substr $last_boundary, -2, 0, "--";

    my $body = $boundary . join( $boundary, @{$content_parts}) . $last_boundary;
    return $body;
}

1;
