package Edge::ClientAPI::Request::_Base;
use common::sense;
use Carp;
use AnyEvent 5.0  ();
use AnyEvent::Log ();
use AnyEvent::HTTP;
use URI;
use JSON::XS;
use Try::Tiny;
use Data::Dumper;
use Safe::Isa;
use Edge::ClientAPI;
use Edge::ClientAPI::Request::_Multipart;
use Edge::ClientAPI::E
    API_REQ_INPUT_INVALID     => [ 5000, "Bad input"      ], # Invalid input data
    API_REQ_AUTH_INVALID      => [ 5010, "Bad auth"       ], # Invalid credentials
    API_REQ_CONN_ERROR        => [ 5020, "Bad connection" ], # 59x HTTP errors
    API_REQ_PROTO_ERROR       => [ 5030, "Bad protocol"   ], # Not expected HTTP statuses
    API_REQ_OUTPUT_INVALID    => [ 5040, "Bad response"   ], # Like API_REQ_PROTO_ERROR, but related to HTTP body
;

use base Exporter::;

our $VERSION = $Edge::ClientAPI::VERSION;
our @EXPORT  = qw(_request _cb_wrap _cb_nowrap
                  is_valid_ip is_valid_username
                  is_valid_password is_valid_guid);

our $USER_AGENT = "Edge-ClientAPI/$VERSION";
my  $JSON       = JSON::XS->new->utf8;

# ----------------------------------------------------------------------
# Callback wrapper
# ----------------------------------------------------------------------
{
    package Edge::ClientAPI::Request::_Callback;
    use strict;
    use warnings;
    use Carp;
    use Safe::Isa;

    sub new {
        my ($class, $cb) = @_;
        return $cb if $cb->$_isa('Edge::ClientAPI::Request::_Callback');
        croak "Not callback" unless ref $cb eq 'CODE';
        my $wrap_cb = sub { # $data, $hdr
            unless ($_[1]{Success}) {
                AE::log error => "Error %s: %s", $_[1]{Code}, $_[1]{Detail};
            }
            $cb->(@_);
            ()
        };
        return bless $wrap_cb, $class;
    }
}

sub _cb_wrap($) {
    my $cb = shift;
    return Edge::ClientAPI::Request::_Callback->new($cb);
}

sub _cb_nowrap($) {
    my $cb = shift;
    croak "Not callback" unless ref $cb eq 'CODE';
    return bless $cb, 'Edge::ClientAPI::Request::_Callback';
}

# ----------------------------------------------------------------------
# Public functions
# ----------------------------------------------------------------------
sub is_valid_ip($) {
    return !is_e Edge::ClientAPI::Data::validate_ipv4($_[0], -nodie);
}

sub is_valid_username($) {
    (!ref $_[0] && length $_[0] && length $_[0] < 128) ? 1 : 0
}

sub is_valid_password($) {
    (!ref $_[0] && length $_[0] && length $_[0] < 128) ? 1 : 0
}

sub is_valid_guid($) {
    return !is_e Edge::ClientAPI::Data::validate_guid($_[0], -nodie);
}

# ----------------------------------------------------------------------
# Private functions
# ----------------------------------------------------------------------
# Catch all data coming through AnyEvent::Handle::push_write and show
# trace log for HTTP requests.
our $orig_cb ||= \&{AnyEvent::Handle::push_write};
our $repl_cb ||= sub {
    AE::log trace => "HTTP request via AnyEvent::HTTP v%s:\n%s",
        $AnyEvent::HTTP::VERSION, $_[1]
        if $_[1] =~ m!^(GET|POST)\s+(\S+)\s+HTTP/1.1\015\012!;
    return $orig_cb->(@_);
};

*AnyEvent::Handle::push_write = $repl_cb
    unless *AnyEvent::Handle::push_write eq $orig_cb;

sub _request($@) {
    my $cb = pop;
    my ($request, %arg) = @_;

    unless (ref $request eq 'HASH') {
        return $cb->(undef, { Code   => API_REQ_INPUT_INVALID,
                              Detail => "No request set" });
    }

    # Validate Operation.
    unless (!ref   $request->{Operation} &&
            length $request->{Operation} &&
                   $request->{Operation} =~ /^\d+$/) {

        return $cb->(undef, {
            %$request,
            Code   => API_REQ_INPUT_INVALID,
            Detail => length $request->{Operation} ? "Invalid operation"
                                                   : "No operation set"
        });
    }

    # Validate Host (ipv4).
    unless (is_valid_ip $request->{Host}) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid IP address" });
    }

    # Validate Port.
    unless (Edge::ClientAPI::Data::validate_port($request->{Port}, -nodie) == 0) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid port" });
    }

    # Validate Method.
    unless ($request->{Method} =~ /^(GET|POST)$/) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid HTTP method" });
    }

    # Validate InputType and OutputType
    unless ($request->{InputType} =~ /^(form|json)$/) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid input type" });
    }

    unless ($request->{OutputType} =~ /(json|plain)/) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid output type" });
    }

    # Prepare URL to make HTTP request.
    my $scheme = $request->{Scheme};
    if (!defined $scheme || $scheme eq '') {
        $scheme = $ENV{EDGE_TEST_API_SCHEME} // 'https';
    }
    $scheme = lc $scheme;
    unless ($scheme =~ /^(https?)$/) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid URL scheme" });
    }

    my $port_suffix = "";
    if (($scheme eq 'https' && $request->{Port} != 443) ||
        ($scheme eq 'http'  && $request->{Port} != 80)) {
        $port_suffix = ":$request->{Port}";
    }

    my $url = new URI sprintf("%s://%s%s/%s/%s",
                              $scheme,
                              $request->{Host},
                              $port_suffix,
                              $request->{Method},
                              $request->{Operation});

    # Prepare input.
    my $body;
    my $has_qs_params = 0;
    if ($request->{InputType} eq 'form') {
        # Method can be GET or POST.
        my $ref = ref $request->{Parameters};

        if ($ref eq 'ARRAY') {
            if (@{$request->{Parameters}}) {
                $url->query_form(@{$request->{Parameters}});
                $has_qs_params = 1;
            }
        } elsif ($ref eq 'HASH') {
            if (keys %{$request->{Parameters}}) {
                $url->query_form($request->{Parameters});
                $has_qs_params = 1;
            }
        }

        if ($request->{Method} eq 'POST') {
            $body = $url->query;   # Get urlencoded HTTP body.
            $url->query_form(+{});
            $has_qs_params = 0;    # All params went to HTTP body.
        }
    }
    else {
        # Input type is JSON. Method can be POST only.
        if ($request->{Method} ne 'POST') {
            return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                             Detail => "Not POST for JSON" });
        }

        # Arrayref or hashref is okay for JSON.
        $body = $JSON->encode($request->{Parameters});
    }

    if (length $request->{QueryString}) {
        # Try to add query string which is not related to POST params or JSON
        # HTTP body.
        if ($has_qs_params) {
            return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                             Detail => "Query string cannot " .
                                                       "be applied" });
        }
    }

    # Prepare HTTP headers.
    my $headers;
    if ($arg{http}) {
        $headers = delete $arg{http}{headers};
        $headers = undef unless ref $headers eq 'HASH';

        # It seems that API doesn't set any cookies, so prepare own cookie jar.
        delete $arg{http}{cookie_jar};
    }

    $headers->{'user-agent'}    //= $USER_AGENT;
    $headers->{'cache-control'}   = "no-store, max-age=0";

    if (defined $body) {
        # That's the way for POST even for JSON data.
        $headers->{'content-type'} = "application/x-www-form-urlencoded; " .
                                     "charset=UTF-8";
    }

    # Add files.
    if ($request->{Files} && %{$request->{Files}}) {
        if ($request->{Method} ne 'POST') {
            return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                             Detail => "Not POST for files" });
        }

        $body = Edge::ClientAPI::Request::_Multipart::body(
                    $request->{Files}, $request->{Parameters}, $headers);
    }

    # Prepare cookie.
    my $cookie_jar;
    if (exists $request->{Cookie}) {
        unless (ref $request->{Cookie} eq 'HASH') {
            return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                             Detail => "Invalid cookie" });
        }

        # Validate GUID if passed.
        if (exists $request->{Cookie}{GUID}) {
            unless (is_valid_guid $request->{Cookie}{GUID}) {
                return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                                 Detail => "Invalid GUID" });
            }
        }

        # Prepare cookie jar.
        my $cookie = +{};

        $cookie_jar = {
            version        => 2,
            $request->{Host} => {
                "/" => $cookie,
            },
        };

        for (keys %{$request->{Cookie}}) {
            # Follow cookie jar format.
            $cookie->{$_} = {
                value  => $request->{Cookie}{$_},
                secure => $scheme eq 'https' ? 1 : 0,
            },
        }

        AE::log trace => "Show cookie jar: %s", Dumper+$cookie_jar;
    }

    # Prepare URL.
    my $url_str = $url->as_string;
    undef $url;

    if (length $request->{QueryString}) {
        # Ensured that query string can be added to this HTTP request.
        $url_str .= '?' if $url_str !~ /\?$/ &&
                           $request->{QueryString} !~ /^\?/;
        $url_str .= $request->{QueryString};
    }

    AE::log info => "Send API request using method %s to '%s'...",
                    $request->{Method}, $url_str;

    # We don't validate SSL certificate - it's private.
    my $queried = AE::time;

    return http_request $request->{Method} => $url_str,
        timeout => 120, # Default timeout. Can be changed by $arg{http}{timeout}.

        %{ $arg{http} },

        defined $body       ? (body       => $body)       : (),
        defined $cookie_jar ? (cookie_jar => $cookie_jar) : (),

        headers    => $headers,
        keepalive  => 1,
        persistent => 1,

        sub {
            my ($body, $hdr) = @_;

            AE::log info => "Received API response from %s request to '%s'...",
                            $request->{Method}, $url_str;

            if (Edge::ClientAPI::Logging::is_debug()) {
                # Body may be large, omit passing it to this subroutine, though
                # trace is off when debug level is off.
                AE::log trace => "HTTP result: %s",
                                 length $body ? $body : '[EMPTY]';
            }

            # Internal params in headers are capitalized.
            $hdr = { %$hdr, %$request, Queried => $queried };
            $hdr->{Success} = 0;

            if ($hdr->{Status} != 200) {
                # Any response other than 200 is error.
                my $reason = $hdr->{Reason};

                if ($hdr->{Status} =~ /^59/) {
                    $hdr->{Code}   = API_REQ_CONN_ERROR;
                    $hdr->{Detail} = $reason;
                } else {
                    $hdr->{Code}   = API_REQ_PROTO_ERROR;
                    $hdr->{Detail} = "HTTP error $hdr->{Status}: $reason";
                }

                $cb->($body, $hdr);
                return;
            }

            my $can_plain = $request->{OutputType} =~ /plain/;
            my $can_json  = $request->{OutputType} =~ /json/;

            if ($can_plain && $can_json) {
                # Note that some responses may be plain text and JSON data for
                # the same requests.

                # Try to determine what is the reponse in fact.
                if ($body =~ /^\s*\{/ && $body =~ /}\s*$/) {
                    # Believe that JSON is a hash object only.
                    $can_plain = 0;
                } else {
                    $can_json  = 0;
                }
            }

            # Now, TRUE is $can_plain or $can_json, not both.
            if ($can_plain) {
                $hdr->{Code}   = 0;
                $hdr->{Detail} = 'OK';
                $hdr->{Success} = 1; # Can be changed in `on_success`.

                $arg{on_success}->($body, $hdr) if $arg{on_success};

                $cb->($body, $hdr);
                return;
            }

            # Parse JSON response.
            my $json = try {
                $JSON->decode($body);
            } catch {
                $hdr->{Detail} = $_;
                $hdr->{Detail} =~ s/\n+$//;
                ()
            };

            unless (ref $json) {
                $hdr->{Code}   = API_REQ_OUTPUT_INVALID;
                $hdr->{Detail} = sprintf "Failed to parse JSON response: %s",
                                         exists $hdr->{Detail} ? $hdr->{Detail}
                                                               : "No detail";
            }
            elsif (ref $json ne 'HASH') {
                $hdr->{Code}   = API_REQ_OUTPUT_INVALID;
                $hdr->{Detail} = "JSON response is not a hashref";
            }
            elsif (exists $json->{LoginStatus} &&
                   $json->{LoginStatus} ne 'OK') {
                $hdr->{Code}   = API_REQ_AUTH_INVALID;
                $hdr->{Detail} = "Invalid authorization: " .
                                 $json->{LoginStatus};
            }
            elsif (!$can_json) {
                $hdr->{Code}   = API_REQ_OUTPUT_INVALID;
                $hdr->{Detail} = "JSON response is not expected, only plain.";
            }

            if (exists $hdr->{Code}) {
                # Problem with the response body.
                $cb->($body, $hdr);
                return;
            }

            # Set `Code` and `Detail` from JSON response.
            $hdr->{Code}    = 0;
            $hdr->{Detail}  = 'OK';
            $hdr->{Success} = 1; # Can be changed in `on_success`.

            $arg{on_success}->($json, $hdr) if $arg{on_success};

            $cb->($json, $hdr);
            ()
        }
    ;
}

1;
