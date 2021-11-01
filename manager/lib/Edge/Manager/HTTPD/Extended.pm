package Edge::Manager::HTTPD::Extended;
use common::sense;
use Try::Tiny;
use Carp;
use Safe::Isa;
use Edge::Manager::HTTPD::Extended::HTTPConnection;
use Edge::Manager::HTTPD::Extended::Response;
use Edge::ClientAPI::E;
use parent qw(AnyEvent::HTTPD);
our $VERSION = 0.01;

our $orig_cb;
BEGIN { $orig_cb      = \&AnyEvent::HTTPD::HTTPServer::new }

our $orig_vars_cb;
BEGIN { $orig_vars_cb = \&AnyEvent::HTTPD::Request::vars }

sub AnyEvent::HTTPD::HTTPServer::new {
    my $this = shift;
    return $orig_cb->($this, connection_class =>
            'Edge::Manager::HTTPD::Extended::HTTPConnection', @_);
}

sub AnyEvent::HTTPD::Request::vars {
    my $this = shift;
    my %vars = $orig_vars_cb->($this);
    for my $val (values %vars) {
        if (ref $val eq 'ARRAY') {
            for (@$val) {
                utf8::decode($_) if !ref $_;
            }
        }
        else {
            utf8::decode($val) if !ref $val;
        }
    }
    %vars
}

sub AnyEvent::HTTPD::Request::response { # $self [, $response ]
    my $self = shift;
    if (@_) {
        croak "Response is not valid ISA"
            unless $_[0]->$_isa('Edge::Manager::HTTPD::Extended::Response');

        return $self->{response} = $_[0];
    }

    return $self->{response} ||= new Edge::Manager::HTTPD::Extended::Response;
}

sub AnyEvent::HTTPD::Request::finish_response {
    my ($self) = @_;
    my $resp = $self->{response};

    croak "No response created" unless $resp;

    my $err;
    try {
        $self->respond([ $resp->code => $resp->status,
                         $resp->get_headers,
                         $resp->get_output ]);
    } catch {
        warn $_;
        $self->respond_500;
    };

    ()
}

sub ERROR_404() {  \& ERROR_404 }
sub throw_404() { die ERROR_404 }

sub AnyEvent::HTTPD::Request::respond_404() {
    my ($self) = @_;

    $self->respond([ 404 => 'Not Found',
                    { 'Content-Type' => 'text/plain' },
                    'Not Found' ]);
    ()
}

sub AnyEvent::HTTPD::Request::respond_500() {
    my ($self) = @_;

    $self->respond([ 500 => 'Internal Error',
                    { 'Content-Type' => 'text/plain' },
                    'Internal Error' ]);
    ()
}

sub AnyEvent::HTTPD::Request::respond_302() {
    my ($self, $location) = @_;

    Carp::croak "Invalid location for 302 redirect"
        unless !ref $location && length $location;

    $location = '/' . $location;

    $self->respond([ 302 => 'Found',
                    { 'Location' => $location },
                    'Redirect' ]);
    ()
}

sub request_cb {
    my $self = shift;

    for (my $i = 0; $i < @_; $i += 2) {
        my $cb = $_[$i + 1];

        $self->reg_cb($_[$i] => sub {
            my ($httpd, $req) = @_;

            $req->response->debug($httpd->{_DEBUG});

            try {
                $cb->($httpd, $req);
            }
            catch {
                $httpd->stop_request;

                if (ref $_ eq 'CODE' && $_ eq ERROR_404) {
                    $req->respond_404($req);
                    return;
                }

                # Send exception.
                if ($req->responded) {
                    AE::log error => "Request responded, log exception: `%s'",
                                     $_;
                    return;
                }

                my $resp = $req->response->success(0);

                if (Edge::ClientAPI::E::is_e) {
                    # Usually, user errors - log them as debug.
                    AE::log debug => "Exception (user error): %s", $_;

                    $resp->error(0+$_);
                    $resp->detail('' . $_);

                    if (!$resp->json && !defined $resp->template) {
                        # to avoid no template error
                        $resp->template('/50x.tmpl');
                    }
                }
                else {
                    # Usually, internal errors - log them as errors.
                    AE::log error => "Exception (app error): %s", $_;

                    $resp->detail('' . $_);
                    # if response is json(1), then template will be ignored
                    $resp->template('/50x.tmpl')
                }

                $resp->reply(version => $Edge::Manager::VERSION);

                try {
                    # some exceptions may be thrown here, so catch them
                    $req->finish_response;
                } catch {
                    AE::log error => "Couldn't respond: `%s'", $_;
                    $req->respond_500($req);
                };
            };
        });
    }

    ()
}

1;
