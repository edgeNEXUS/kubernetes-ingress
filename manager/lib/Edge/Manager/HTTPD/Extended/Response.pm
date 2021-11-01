package Edge::Manager::HTTPD::Extended::Response;
use common::sense;
use boolean;
use Carp;
use Scalar::Util;

our $JSON_CODER;

sub __json_coder() {
    $JSON_CODER //= eval { require JSON::XS; JSON::XS->new->utf8 } ||
                     do  { require JSON::PP; JSON::PP->new->utf8 };

    $JSON_CODER->pretty(1)
               ->relaxed(1)
               ->convert_blessed(1);

    return $JSON_CODER;
}

sub UNIVERSAL::TO_JSON {
    if (Scalar::Util::blessed $_[0]) {
        if ($_[0]->can('as_hashref')) {
            return $_[0]->as_hashref(-outfit => 1);
        } elsif ($_[0]->can('as_arrayref')) {
            return $_[0]->as_arrayref(-outfit => 1);
        } elsif ($_[0]->can('as_string')) {
            return $_[0]->as_string;
        } else {
            croak "No idea how to convert class `", ref $_[0], "' to JSON";
        }
    }

    undef
}

sub new {
    my ($class) = @_;
    unless ($Edge::Manager::Template::Static::VERSION) {
        eval q{require Edge::Manager::Template::Static};
    }

    my $self = {
            code     => 200,   # HTTP code
            status   => "OK",  # HTTP status
            json     => 0,     # for HTTP content-type
            template => undef, # template filename
            debug    => 0,

            success  => boolean::false, #undef, # operation success or not
            detail   => undef, # operation or error details
            error    => undef, # error code, a number if defined

            reply    => +{},
    };

    bless $self, $class
}

sub debug {
    @_ > 1 ? ($_[0]{debug} = !!$_[1]) : $_[0]{debug};
}

sub code { # $self
    croak "No code setter" if @_ > 1;
    return $_[0]{code};
}

sub status { # $self
    croak "No status setter" if @_ > 1;
    return $_[0]{status};
}

sub success { # $self, [, $success ]
    my $self = shift;

    if (@_) {
        $self->{success} = $_[0] ? boolean::true : boolean::false;
        return $self;
    }

    return $self->{success};
}

sub detail { # $self [, $detail ]
    my $self = shift;

    if (@_) {
        if (defined $_[0]) {
            unless (!ref $_[0] && length $_[0]) {
                $self->{detail} = '' . $_[0];
            }
        }

        $self->{detail} = $_[0];
        return $self;
    }

    return $self->{detail};
}

sub error { # $self [, $code ]
    my $self = shift;

    if (@_) {
        if (defined $_[0]) {
            croak "Invalid error code"
                unless !ref $_[0] && $_[0] =~ /^\d+$/;

            my $err = int $_[0];

            croak "Invalid error code number"
                unless $err >= 0 && $err <= 0xFFFFFFFF && $_[0] eq $err;

            croak "Error is being set for successfull response"
                if $self->success;

            $self->{error} = $err;
        }
        else {
            $self->{error} = undef;
        }

        return $self;
    }

    return $self->{error};
}

sub set_e {
    my ($self, $e) = @_;

    croak "Invalid exception"
        unless is_e $e;

    $self->error(int $e);
    $self->detail("" . $e);
    ()
}

sub json { # $self [, $json ]
    my $self = shift;

    if (@_) {
        $self->{json} = $_[0] ? 1 : 0;
        return $self;
    }

    return $self->{json};
}

sub template { # $self [, $filename ]
    my $self = shift;

    if (@_) {
        if (defined $_[0]) {
            croak "Invalid template filename"
                unless !ref $_[0] && length $_[0];
        }

        $self->{template} = $_[0];
        return $self;
    }

    return $self->{template};
}

sub reply { # $self [, $param1 => $value1 [, ... [ , $paramN => $valueN ] ] ]
    my $self = shift;

    if (@_) {
        my %reply = @_;

        for (keys %reply) {
            $self->{reply}{$_} = $reply{$_};
        }

        return $self;
    }

    return $self->{reply};
}

#-----------------------------------------

sub get_headers {
    return $_[0]->json ? { 'Content-Type' => 'application/json' }
                       : { 'Content-Type' => 'text/html' };
}

sub get_vars {
    my $self = shift;

    my $ret  = {
        success => $self->success, # always defined
        detail  => $self->detail,  # can be undef
        error   => $self->error,
        reply   => $self->reply,   # can be empty hashref
    };

    return $ret;
}

sub get_template_output {
    my $self = shift;
    my $tmpl = new Edge::Manager::Template::Static TRIM => 1, NOXSS => 1;

    croak "No template filename set"
        unless defined $self->template;

    my $vars = $self->get_vars;
    if ($self->debug) {
        $vars->{debug} = { data => __json_coder->pretty(1)->encode($vars) };
    }

    $tmpl->process_static($self->template, $vars, \ my $output);

    if (utf8::is_utf8 $output) {
        # "\x{100}" becomes "\xc4\x80"
        utf8::encode $output;
    }

    #utf8::downgrade $output;

    return $output;
}

sub get_output {
    my $self = shift;

    if ($self->json) {
        return __json_coder->encode($self->get_vars);
    }
    else {
        return $self->get_template_output;
    }
}

sub noreply {
    my $self = shift;
    $self->{reply} = +{};
    $self
}

1;
