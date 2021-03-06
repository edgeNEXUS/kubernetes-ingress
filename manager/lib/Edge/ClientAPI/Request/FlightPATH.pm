package Edge::ClientAPI::Request::FlightPATH;
use common::sense;
use Data::Dumper;
use Safe::Isa;
use Try::Tiny;
use AnyEvent::Tools;
use AnyEvent::ForkObject;
use Edge::ClientAPI;
use Edge::ClientAPI::Request::_Base;
use Edge::ClientAPI::Request::alb_api;
use Edge::ClientAPI::Object::VS;
use Edge::ClientAPI::Object::FP;
use Edge::ClientAPI::E;

use base Exporter::;
our $VERSION = $Edge::ClientAPI::VERSION;
our @EXPORT  = qw(create_fp_custom_forward
                  remove_fp_custom_forward
                  get_fps
                  apply_fp_by_name
                  unapply_fp_by_name
                  remove_fp_by_id);

sub Edge::ClientAPI::Request::alb_api::error {
    my ($msg, $fatal) = @_;
    if ($fatal) {
        $msg .= "\n" unless $msg =~ /\n$/;
        die $msg;
    } else {
        AE::log warn => "%s", $msg;
    }

    ()
}

sub Edge::ClientAPI::Request::alb_api::debug {
    AE::log debug => "%s", join('', @_);
}

# ----------------------------------------------------------------------
# Private functions for API
# ----------------------------------------------------------------------
sub __fo {
    my $method = pop;
    my $cb     = _cb_wrap pop;
    my $fo     = AnyEvent::ForkObject->new;

    $fo->do(
        module => 'Edge::ClientAPI::Request::FlightPATH',
        method => $method,
        args   => [ @_ ],
        cb     => sub {
            my ($status) = @_;

            if ($status eq 'die') {
                my %hdr = (Success => 0,
                           Code    => Edge::ClientAPI::EDGE_ERROR(),
                           Detail  => $_[1]);
                $cb->(undef, \%hdr);
                return;
                ()
            }
            elsif ($status eq 'fatal') {
                my %hdr = (Success => 0,
                           Code    => Edge::ClientAPI::EDGE_ERROR(),
                           Detail  => "Fork error: $_[1]");
                $cb->(undef, \%hdr);
                return;
            }

            $cb->(undef, { Success => 1 });
            ()
        },
    );

    return $fo;
}

sub _get_fps_from_json(\%) {
    my $json = shift;

    return undef unless ref $json->{dataset} eq 'HASH';
    return undef unless ref $json->{dataset}{row} eq 'ARRAY' ||
                        $json->{dataset}{row} eq '';

    my $row = $json->{dataset}{row};
    unless (ref $row eq 'ARRAY') {
        return []; # No FPs in valid response from the ADC.
    }

    for my $fp (@$row) {
        Edge::ClientAPI::Object::FP->bless($fp);
    }

    return $row;
}

# ----------------------------------------------------------------------
# Public functions for API
# ----------------------------------------------------------------------
sub create_fp_custom_forward {
    return __fo(@_, '__create_fp_custom_forward');
}

sub remove_fp_custom_forward {
    return __fo(@_, '__remove_fp_custom_forward');
}

sub get_fps {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my %arg     = @_;
    my $request = { Operation   => 11,
                    Method      => 'GET',
                    InputType   => 'form',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid   },
                    Parameters  => +{} };

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;
        $_[0] = _get_fps_from_json %$json;
        ()
    };

    return _request($request, %arg, $cb);
}

sub apply_fp_by_name {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $name    = shift;
    my $vs      = shift;
    my %arg     = @_;
    my $options = +{};
    my $request = { Operation   => 9,
                    Method      => 'POST',
                    QueryString => 'iAction=4&iType=1',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID => $creds->guid },
                    Parameters  => $options };

    unless (!ref $name && length $name) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                        Detail => "Invalid flightPATH name for apply" });
    }

    unless ($vs->$_isa('Edge::ClientAPI::Object::VS')) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                        Detail => "Invalid VS object" });
    }

    $options->{editedInterface}    = $vs->interface_id;
    $options->{editedChannel}      = $vs->channel_id;
    $options->{CheckChannelKey}    = $vs->channel_key;
    $options->{flightPathName}     = $name;
    $options->{flightPathDropName} = '';
    $options->{flightPathDropId}   = '';

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;

        if (defined $json->{StatusImage} &&
            $json->{StatusText} ne 'Your changes have been applied') {

            if ($json->{StatusText} =~ /Terminal flightPATH rule .*? can prevent later rules from running./) {
                # Issue a warning message
                AE::log warn => "ALB API request to apply FPs raised a " .
                                "warning in apply_by_id(): " .
                                "'%s'", $json->{StatusText};
            }
            else {
                $hdr->{Success} = 0;
                $hdr->{Detail}  = "ALB API request to apply FPs failed in " .
                                  "apply_fp_by_id(): '%s'", $json->{StatusText};
            }
        }

        if ($hdr->{Success}) {
            $_[0] = _get_fps_from_json %$json;
        } else {
            $_[0] = undef;
        }

        ()
    };

    return _request($request, %arg, $cb);
}

sub unapply_fp_by_name {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $name    = shift;
    my $vs      = shift;
    my %arg     = @_;
    my $options = +{};
    my $request = { Operation   => 9,
                    Method      => 'POST',
                    QueryString => 'iAction=4&iType=2',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID => $creds->guid },
                    Parameters  => $options };

    unless (!ref $name && length $name) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                        Detail => "Invalid flightPATH name for unapply" });
    }

    unless ($vs->$_isa('Edge::ClientAPI::Object::VS')) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                        Detail => "Invalid VS object" });
    }

    $options->{editedInterface}    = $vs->interface_id;
    $options->{editedChannel}      = $vs->channel_id;
    $options->{CheckChannelKey}    = $vs->channel_key;
    $options->{flightPathName}     = $name;
    $options->{flightPathDropName} = '';
    $options->{flightPathDropId}   = '';

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;

        if (defined $json->{StatusImage} &&
            $json->{StatusText} ne 'Your changes have been applied') {

            if ($json->{StatusText} =~ /Terminal flightPATH rule .*? can prevent later rules from running./) {
                # Issue a warning message
                AE::log warn => "ALB API request to unapply FPs raised a " .
                                "warning in unapply_by_id(): " .
                                "'%s'", $json->{StatusText};
            }
            else {
                $hdr->{Success} = 0;
                $hdr->{Detail}  = "ALB API request to unapply FPs failed in " .
                                  "unapply_fp_by_id(): '%s'",
                                  $json->{StatusText};
            }
        }

        if ($hdr->{Success}) {
            $_[0] = _get_fps_from_json %$json;
        } else {
            $_[0] = undef;
        }

        ()
    };

    return _request($request, %arg, $cb);
}

sub remove_fp_by_id {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $id      = shift;
    my %arg     = @_;
    my $request = { Operation   => 11,
                    Method      => 'POST',
                    QueryString => 'iAction=3&iType=1',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID => $creds->guid },
                    Parameters  => { fId  => "" . $id } };

    unless (!ref $id && length $id) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                        Detail => "Invalid flightPATH ID for removal" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;

        if (defined $json->{StatusImage} &&
            $json->{StatusText} ne 'Your changes have been applied') {

            $hdr->{Success} = 0;
            $hdr->{Detail}  = "ALB API request to remove a FP $id failed in " .
                              "remove_fp_by_id(): '$json->{StatusText}'";
        }

        if ($hdr->{Success}) {
            $_[0] = _get_fps_from_json %$json;
        } else {
            $_[0] = undef;
        }

        ()
    };

    return _request($request, %arg, $cb);
}

# ----------------------------------------------------------------------
# Private functions for API
# ----------------------------------------------------------------------
sub __create_fp_custom_forward {
    my $class      = shift;
    my $creds      = shift;
    my $domain     = shift;
    my $vs_has_fp  = shift;
    my $vs_ip      = shift; # VS by IP/Port must exist.
    my $vs_port    = shift;
    my $fp_name    = shift; # flightPATH to be created.
    my $fp_desc    = shift;
    my $rs_host    = shift; # RS on VS must exist.
    my $rs_port    = shift;
    my $path_start = shift;
    my %arg        = @_;

    unless ($creds->$_isa('Edge::ClientAPI::Creds')) {
        $creds = Edge::ClientAPI::Creds->new(%$creds);
    }

    # If FP is not found, error is not to be raised.
    __remove_fp_custom_forward(undef, $creds, $vs_has_fp, $fp_name, %arg);

    AE::log info => "Create flightPATH with name '%s' from scratch...",
                    $fp_name;
    my $fp_id;

    {
        my $href = Edge::ClientAPI::Request::alb_api::create_fp(
                        $creds->get_url,
                        $creds->guid,
                        $fp_name,
                        $fp_desc);

        if (ref $href->{dataset}{row} eq 'ARRAY') {
            for my $row (@{$href->{dataset}{row}}) {
                if ($row->{flightPathName} eq $fp_name) {
                    $fp_id = $row->{fId};
                    AE::log debug => "New flightPATH with name '%s' got ID %s",
                                     $fp_name, $fp_id;
                    last;
                }
            }
        }

        unless (length $fp_id) {
            Edge::ClientAPI::Request::alb_api::error(
                    "Couldn't create flightPATH with name '$fp_name'");
            return;
        }
    }

    AE::log info => "Create condition 'Host' for flightPATH with name '%s'...",
                    $fp_name;

    my $href = Edge::ClientAPI::Request::alb_api::create_fp_condition(
                        $creds->get_url,
                        $creds->guid,
                        $fp_id,
                        $fp_name,
                        "Host",
                        "",
                        "Does",
                        "Equal",
                        $domain
    );

    AE::log info => "Create condition 'Path' for flightPATH with name '%s'...",
                    $fp_name;

    my $href = Edge::ClientAPI::Request::alb_api::create_fp_condition(
                        $creds->get_url,
                        $creds->guid,
                        $fp_id,
                        $fp_name,
                        "Path",
                        "",
                        "Does",
                        "Start",
                        $path_start
    );

    AE::log info => "Create action 'Use Server' for flightPATH " .
                    "with name '%s'...", $fp_name;
    my $href = Edge::ClientAPI::Request::alb_api::create_fp_action(
                        $creds->get_url,
                        $creds->guid,
                        $fp_id,
                        $fp_name,
                        "Use Server",
                        "$rs_host:$rs_port",
                        undef
    );

    #AE::log info => "Create action 'Replace Request Header' for flightPATH " .
    #                "with name '%s'...", $fp_name;
    #
    #my $href = Edge::ClientAPI::Request::alb_api::create_fp_action(
    #                    $creds->get_url,
    #                    $creds->guid,
    #                    $fp_id,
    #                    $fp_name,
    #                    "Replace Request Header",
    #                    "$rs_host",
    #                    undef
    #);

    my $href = Edge::ClientAPI::Request::alb_api::manage_vs_fps(
                        $creds->get_url,
                        $creds->guid,
                        'apply', # Action.
                        "",      # Service name.
                        $vs_ip,
                        "",      # Subnet.
                        $vs_port,
                        "HTTP",
                        [ $fp_name ],
    );

    # Determine flightPATH for drag-n-drop
    my $found_vs;
    my $list = $href->{data}{dataset}{ipService};

    if (ref $list eq 'ARRAY') {
        FIRST_LIST: for my $list2 (@$list) {
            next unless ref $list2 eq 'ARRAY';
            for my $vs (@$list2) {
                next unless ref $vs eq 'HASH';
                Edge::ClientAPI::Object::VS->bless($vs);

                if ($vs) {
                    if ($vs->ip   eq $vs_ip &&
                        $vs->port eq $vs_port &&
                        $vs->service_type eq 'HTTP') {
                        # Got VS with applied flightPATH
                        $found_vs = $vs;
                        last FIRST_LIST;
                    }
                }
            }
        }
    }

    if ($found_vs) {
         # Move the FP to the top of the list of the FPs applied to the VS
        my $top_fp_name = $found_vs->get_fp_name_by_idx(1);
        my $top_fp_idx  = 1;

        if (length $top_fp_name && $top_fp_name ne $fp_name) {
            my $fp_idx = $found_vs->get_fp_idx_by_name($fp_name);

            if ($fp_idx > 0 && $top_fp_idx != $fp_idx) {

                AE::log debug => "Ready to move FP '%s' (index %d) to the top instead of '%s' (index %d)",
                                 $fp_name, $fp_idx, $top_fp_name, $top_fp_idx;

                my %hash = (
                    flightPathDragId   => $fp_idx,
                    flightPathDragName => $fp_name,
                    flightPathDropId   => $top_fp_idx,
                    flightPathDropName => $top_fp_name,
                );
                AE::log trace => "Data for flightPATH drag-n-drop: %s",
                                 Dumper+\%hash;

                my $href = Edge::ClientAPI::Request::alb_api::manage_vs_fps_by_ids(
                                    $creds->get_url,
                                    $creds->guid,
                                    'drag-n-drop', # Action.
                                    $found_vs->interface_id,
                                    $found_vs->channel_id,
                                    $found_vs->channel_key,
                                    [ \%hash ],
                );
            }
        }
    }

    ()
}

sub __remove_fp_custom_forward {
    my $class     = shift;
    my $creds     = shift;
    my $vs_has_fp = shift;
    my $fp_name   = shift;
    my %arg       = @_;

    unless ($creds->$_isa('Edge::ClientAPI::Creds')) {
        $creds = Edge::ClientAPI::Creds->new(%$creds);
    }

    #push @$vs_has_fp, undef unless @$vs_has_fp;

    for my $vs (@$vs_has_fp) {
        # ForkObject sends unblessed objects.
        if (defined $vs && !$vs->$_isa('Edge::ClientAPI::Object::VS')) {
            Edge::ClientAPI::Object::VS->bless($vs);
        }

        try {
            AE::log info => "Unapply flightPATH with name '%s'...", $fp_name;
            my $href = Edge::ClientAPI::Request::alb_api::manage_vs_fps_by_ids(
                                $creds->get_url,
                                $creds->guid,
                                'unapply', # Action.
                                $vs->interface_id,
                                $vs->channel_id,
                                $vs->channel_key,
                                [ $fp_name ],
            );
        }
        catch {
            if (/Virtual service .+ not found in/i) {
                # Ignore this error. No VS, no need to unapply.
                AE::log debug => "%s", $_;
            } elsif (/Flightpath name is not in list/i) {
                # Ignore this error. No flightPATH, no need to unapply.
                AE::log debug => "%s", $_;
            } else {
                die $_;
            }
        };
    }

    try {
        AE::log info => "Remove flightPATH by name '%s'...", $fp_name;
        Edge::ClientAPI::Request::alb_api::remove_fp(
                    $creds->get_url,
                    $creds->guid,
                    "",
                    $fp_name);
    }
    catch {
        if (/Requested flightPATH .+ not found in/i) {
            # Ignore this error. No FP, no need to remove.
            AE::log debug => "%s", $_;
        } else {
            die $_;
        }
    };

    ()
}

1;
