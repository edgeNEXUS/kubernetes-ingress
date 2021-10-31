package Edge::ClientAPI::Request::IPServicesApi;
use common::sense;
use Data::Dumper;
use Safe::Isa;
use AnyEvent::Tools;
use Edge::ClientAPI;
use Edge::ClientAPI::Request::_Base;
use Edge::ClientAPI::E
    API_REQ_VS_NOT_FOUND  => [ 5200, "Virtual service not found" ],
    API_REQ_VS_EXISTS     => [ 5201, "Virtual service already exists" ],
    API_REQ_VS_CSERVER_ID => [ 5202, "CServerId is not found on VS" ],
;

use base Exporter::;
our $VERSION = $Edge::ClientAPI::VERSION;
our @EXPORT  = qw(update_vs get_all_vs get_vs create_empty_vs create_vs
                  delete_vs delete_vs_by_specs
                  change_basic_settings enable_ssl_vs_by_specs disable_ssl_vs_by_specs
                  update_rs upsert_rs init_rs_multi init_rs_multi_by_specs
                  create_rs_empty remove_rs_by_specs remove_rs);

# ----------------------------------------------------------------------
# Private functions
# ----------------------------------------------------------------------
sub _find_vs(\@@) {
    my $vips = shift;
    my ($serviceName, $ipAddr, $subnetMask, $port, $serviceType,
        $CSIPAddr, $CSPort, $returnRS) = @_; # 8 arguments.

    my $res = +{}; # To be last found VS using filter?

    # Copied from alb_api.pm/find_vs(): Don't touch.
    foreach my $vss_ref (@$vips) {
        foreach my $vs (@{$vss_ref}) {
            #debug("VS:\n" . encode_json($vs) . "\n");
            my ($serviceNameCmp, $ipAddrCmp, $subnetMaskCmp, $portCmp, $serviceTypeCmp, $CSIPAddrCmp, $CSPortCmp) = 
               ('', '', '', '', '', '', '');
            if (defined($serviceName) && ($serviceName ne '')) {
                $serviceNameCmp = $vs->{'serviceName'};
            } else {
                $serviceName = '';
            }
            if (defined($ipAddr) && ($ipAddr ne '')) {
                $ipAddrCmp = $vs->{'ipAddr'};
            } else {
                $ipAddr = '';
            }
            if (defined($subnetMask) && ($subnetMask ne '')) {
                $subnetMaskCmp = $vs->{'subnetMask'};
            } else {
                $subnetMask = '';
            }
            if (defined($port) && ($port ne '')) {
                $portCmp = $vs->{'port'};
            } else {
                $port = '';
            }
            if (defined($serviceType) && ($serviceType ne '')) {
                $serviceTypeCmp = $vs->{'serviceType'};
            } else {
                $serviceType = '';
            }
            if (!defined($CSIPAddr)) {
                $CSIPAddr = '';
            }
            if (!defined($CSPort)) {
                $CSPort = '';
            }

            if (($serviceNameCmp eq $serviceName) && 
                ($ipAddrCmp eq $ipAddr) && ($subnetMaskCmp eq $subnetMask) && 
                ($portCmp eq $port) && ($serviceTypeCmp eq $serviceType)) {

                if (($CSIPAddr ne '') || ($CSPort ne '')) {
                    # Get Content Servers of a Virtual Service
                    my @css;
                    if (defined($vs->{'contentServer'}) && ($vs->{'contentServer'} ne "")) {
                        @css = $vs->{'contentServer'}->{'CServerId'};
                    }
                    if (scalar(@css) > 0) {
                        foreach my $cs_arref (@css) {  
                            if (scalar(@$cs_arref) > 0) {
                            foreach my $cs (@$cs_arref) {  
                                if ($CSIPAddr ne '') {
                                    $CSIPAddrCmp = $cs->{'CSIPAddr'};
                                }
                                if ($CSPort ne '') {
                                    $CSPortCmp = $cs->{'CSPort'};
                                }
                                if (($CSIPAddrCmp eq $CSIPAddr) && ($CSPortCmp eq $CSPort)) {
                                    if (defined($returnRS) && $returnRS) {
                                        # Add VS data required for upating the RS
                                        $cs->{'editedInterface'} = $vs->{'InterfaceID'};
                                        $cs->{'editedChannel'} = $vs->{'ChannelID'};
                                        $cs->{'CheckChannelKey'} = $vs->{'ChannelKey'};
                                        $res = $cs;
                                    } else {
                                        $res = $vs;
                                    }
                                    last;
                                }
                            }
                            }
                        }
                    }
                } else {
                    if (defined($returnRS) && $returnRS) {
                        $res = ();
                    } else {
                        $res = $vs;
                    }
                    last;
                }
            }
        }
    }

    return %$res ? $res : undef;
}

sub _find_vs_by_ids(\@$$) {
    my ($vips, $iface_id, $channel_id) = @_;
    return undef unless length $iface_id && length $channel_id;

    for my $vss_ref (@$vips) {
        for my $vs (@$vss_ref) {
            if ($vs->{InterfaceID} eq $iface_id &&
                $vs->{ChannelID}   eq $channel_id) {
                return $vs;
            }
        }
    }
    return undef;
}

sub _try_to_populate_error($$$$) {
    my ($json, $hdr, $func_name, $spec) = @_;
    $spec //= "update a VS";

    if (defined $json->{StatusImage} &&
        $json->{StatusText} ne 'Your changes have been applied') {

        if ($json->{StatusImage} eq 'jetWarning' ||
            $json->{StatusText} =~ /RDP works better with Load Balancing Policy RDP Cookie Persisten[cs]e/ ||
            $json->{StatusText} =~ /RDP will correct work with load balancing policy RDP Cookie Persisten[cs]e/ ||
            $json->{StatusText} =~ /RDP will work correctly with load balancing policy RDP Cookie Persisten[cs]e/ ||
            $json->{StatusText} =~ /RDP works better with load balancing policy RDP Cookie Persistence/ ||
            $json->{StatusText} =~ /IP address \S+ is on the Add-Ons virtual network/ ||
            $json->{StatusText} =~ /"TCP Connection" may be better monitored before "200OK"/) {
            # TODO: add warning to API response?
            AE::log warn => "ALB API request to %s raised a warning in " .
                            "%s(): '%s'",
                            $spec, $func_name, $json->{StatusText};
        } else {
            $json->{StatusText} ||= 'unknown error';
            $hdr->{Success} = 0;
            $hdr->{Detail}  = "ALB API request to $spec failed " .
                              "failed in $func_name(): " .
                              "'$json->{StatusText}'";
        }
    }
    ()
}

sub _get_vips_from_json(\%) {
    my $json = shift;
    return undef unless ref $json->{data} eq 'HASH';
    return undef unless ref $json->{data}{dataset} eq 'HASH';
    return undef unless ref $json->{data}{dataset}{ipService} eq 'ARRAY' ||
                        $json->{data}{dataset}{ipService} eq '';

    # Validate response with ipService (arrayref or empty string).
    my $vips = $json->{data}{dataset}{ipService};
    unless (ref $vips eq 'ARRAY') {
        return []; # No virtual services in valid response from the ADC.
    }

    # Bless all virtual services
    for my $vss_ref (@$vips) {
        for my $vs (@{$vss_ref}) {
            Edge::ClientAPI::Object::VS->bless($vs);
        }
    }

    return $vips;
}

# ----------------------------------------------------------------------
# Public functions for API
# ----------------------------------------------------------------------
# Update Virtual Service data
# If $what == 'service', main data (IP, mask, port, etc) of the VS are updated
# If $what == 'basic', basic tab data (monitoring, LB policy, etc) of the VS are updated
# If $what == 'advanced', advanced tab data of the VS are updated
# If $what == 'ssl-client-authentication', SSL CLient Authentication data of the VS are updated
sub update_vs {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $vs      = shift; # `ipAddr`, `subnetMask`, etc., update-specific params
    my $what    = shift; # String.
    my %arg     = @_;
    my $qs      = undef;

    if    ($what eq 'service')                   { $qs = 'iAction=2&iType=1' }
    elsif ($what eq 'basic')                     { $qs = 'iAction=2&iType=3' }
    elsif ($what eq 'advanced')                  { $qs = 'iAction=2&iType=4' }
    elsif ($what eq 'ssl-client-authentication') { $qs = 'iAction=2&iType=7' }
    elsif ($what eq 'load-balancing')            { $qs = 'iAction=2&iType=9' }

    my $request = { Operation   => 9,
                    Method      => 'POST',
                    QueryString => $qs,
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid },
                    Parameters  => $vs };

    unless (defined $qs) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Incorrect 'what' value in update_vs()" });
    }
    unless ($vs->$_isa('Edge::ClientAPI::Object::VS') || ref $vs eq 'HASH') {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Incorrect 'vs' value in update_vs()" });
    }

    unless (length $vs->{editedInterface} &&
            length $vs->{editedChannel}   &&
            length $vs->{CheckChannelKey}) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                 Detail => "No update-specific params found" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;
        # Check JSON for StatusText and set error (if any).
        _try_to_populate_error $json, $hdr, 'update_vs', 'update a VS';
        return unless $hdr->{Success};

        my $vips = _get_vips_from_json %$json; # Can be undefined.
        if (defined $vips) {
            my $updated = _find_vs(@$vips,
                                   $vs->{serviceName}, $vs->{ipAddr},
                                   $vs->{subnetMask},  $vs->{port},
                                   $vs->{serviceType});
            if ($updated) {
                # Success.
                AE::log info => "Virtual service with interface ID %s, " .
                                "channel key %s has been updated",
                                $vs->{editedChannel}, $vs->{editedChannel};
                $_[0] = $updated;
                return;
            }
        }

        $hdr->{Success} = 0;
        $hdr->{Detail}  = "Unable to find the updated VS in update_vs()";
        ()
    };

    AE::log info => "Update virtual service with interface ID %s, " .
                    "channel key %s (%s)", $vs->{editedChannel},
                                           $vs->{editedChannel}, $what;
    return _request($request, %arg, $cb);
}

sub get_all_vs {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my %arg     = @_;
    my $options = +{};
    my $request = { Operation   => 9,
                    Method      => 'GET',
                    InputType   => 'form',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid },
                    Parameters  => $options };

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;
        my $vips = _get_vips_from_json %$json;

        if (($json->{StatusText} eq 'Your changes have been applied' ||
             $json->{StatusText} eq 'get') &&
            defined $vips) {
            # It's valid response if $vips is empty array.
            my $vs_num = 0;
            for my $vss_ref (@$vips) {
                $vs_num++ for @$vss_ref; # Enumerate VS.
            }

            AE::log info => "Found %d virtual service(s)", $vs_num;
            $_[0] = $vips;
        }
        else {
            $json->{StatusText} ||= 'unknown error';
            $hdr->{Success} = 0;
            $hdr->{Detail}  = "ALB API request to get all VS failed in " .
                              "get_all_vs(): '$json->{StatusText}'";
        }
        ()
    };

    AE::log info => "Get all Virtual Services...";
    return _request($request, %arg, $cb);
}

sub get_vs {
    my $cb     = _cb_wrap pop;
    my $creds  = shift;
    my @filter = splice @_, 0, 8; # e.g. `serviceName`, `ipAddr`, etc.
    my %arg    = @_;
    my $new_cb = _cb_nowrap sub {
        my ($vips, $hdr) = @_;
        if (!$hdr->{Success}) {
            $cb->(@_);
            return;
        }

        my $found;
        if (@$vips) {
            $found = _find_vs @$vips, @filter; # Hashref of found VS or undef.
        }

        unless (defined $found) {
            $hdr->{Success} = 0;
            $hdr->{Detail}  = sprintf "Not found virtual service by filter: " .
                                      "[%s]", join(', ', @filter);
            $hdr->{Code}    = API_REQ_VS_NOT_FOUND;
        } else {
            AE::log info => "Found virtual service by filter: [%s]",
                            join(', ', @filter);
        }

        $cb->($found, $hdr);
        ()
    };

    AE::log info => "Get virtual service by filter: [%s]", join(', ', @filter);
    return get_all_vs($creds, %arg, $new_cb);
}

sub create_empty_vs {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my %arg     = @_;
    my $options = +{};
    my $request = { Operation   => 9,
                    Method      => 'POST',
                    QueryString => 'iAction=3&iType=1',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid },
                    Parameters  => $options };

    $options->{editedInterface} = "";
    $options->{editedChannel}   = "";
    $options->{CheckChannelKey} = "";
    $options->{CopyVIP}         = "0";

    # Send two requests one after one. TODO: Use promises.
    my $guard  = 1;
    my $new_cb = _cb_nowrap sub {
        $guard &&= 1 or return;
        my (undef, $hdr) = @_;
        if (!$hdr->{Success}) {
            $cb->(@_);
            return;
        }

        $arg{on_success} = sub {
            return unless $guard;
            my ($json, $hdr) = @_;
            # Check JSON for StatusText and set error (if any).
            _try_to_populate_error $json, $hdr, 'create_empty_vs',
                                                'create a VS';
            return unless $hdr->{Success};

            my $vips = _get_vips_from_json %$json; # Can be undefined.
            if (defined $vips) {
                my $empty = _find_vs(@$vips, "", "", "", "", "");
                if ($empty) {
                    # Success.
                    AE::log info => "Empty slot for Virtual Service is created";
                    $_[0] = $empty;
                    return;
                }
            }

            $hdr->{Success} = 0;
            $hdr->{Detail}  = "Unable to find the created VS in " .
                              "create_empty_vs()";
            ()
        };

        # Finally, create an "empty" virtual service.
        AE::log info => "Create an empty slot for Virtual Service...";
        return $guard = _request($request, %arg, $cb);
    };

    # Do not get all virtual services to create empty slot for virtual service.
    #$guard = get_all_vs($creds, %arg, $new_cb);
    $new_cb->(undef, { Success => 1 });
    return defined wantarray && AnyEvent::Util::guard { undef $guard };
}

sub create_vs {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my @vs      = splice @_, 0, 7;
    my %arg     = @_;
    my $options = +{};
    my $request = { Operation   => 9,
                    Method      => 'GET',
                    InputType   => 'form',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid },
                    Parameters  => $options };

    $_ = "$_" for @vs; # Stringify.

    my ($serviceName, $ipAddr, $subnetMask, $port,
        $serviceType, $sslCertificate, $rss_ref) = @vs;

    # $serviceName is optional.
    unless (length $ipAddr && length $subnetMask &&
            length $port && length $serviceType) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                            Detail => "Not all mandatory arguments provided" });
    }

    if (length $sslCertificate || length $rss_ref) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
             Detail => "SSL certificate or remote services are not accepted" });
    }

    my $guard  = 1;
    my $new_cb = _cb_nowrap sub {
        $guard &&= 1 or return;
        my ($found, $hdr) = @_;

        if ($hdr->{Code} != API_REQ_VS_NOT_FOUND) {
            if ($hdr->{Success}) {
                $hdr->{Success} = 0;
                $hdr->{Code}    = API_REQ_VS_EXISTS;
                $hdr->{Detail}  = "" . e40 API_REQ_VS_EXISTS;
            }

            $cb->(@_);
            return;
        }

        my $new_cb = _cb_nowrap sub {
            $guard &&= 1 or return;
            my ($empty, $hdr) = @_;
            if (!$hdr->{Success}) {
                $cb->(@_);
                return;
            }

            my $vs;
            $vs->{CopyVIP}                 = "0";
            $vs->{editedInterface}         = $empty->{InterfaceID};
            $vs->{editedChannel}           = $empty->{ChannelID};
            $vs->{CheckChannelKey}         = $empty->{ChannelKey};
            $vs->{serviceName}             = $serviceName;
            $vs->{ipAddr}                  = $ipAddr;
            $vs->{subnetMask}              = $subnetMask;
            $vs->{port}                    = $port;
            $vs->{serviceType}             = $serviceType;
            $vs->{localPortEnabledChecked} = 'true';

            AE::log info => "Update empty slot in order to set data...";
            $guard = update_vs($creds, $vs, 'service', %arg, $cb);
            ()
        };

        AE::log info => "Create VS %s/%s:%s...", $ipAddr, $subnetMask, $port;

        # Second, create an "empty" service.
        $guard = create_empty_vs($creds, %arg, $new_cb);
        ()
    };

    unless ($arg{-no_vs_existing_check}) {
        # First, ensure there's no such virtual service.
        $guard = get_vs($creds, $serviceName, $ipAddr, $subnetMask, $port,
                         $serviceType, undef, undef, undef, %arg, $new_cb);
    } else {
        # We trust that there's no such virtual service. The caller must do
        # all the checks by itself, if needed (or do not use
        # `-no_vs_existing_check`).
        AE::log info => "Create VS %s/%s:%s without existence check...",
                        $ipAddr, $subnetMask, $port;
        $guard = 1;
        $new_cb->(undef, { Code => API_REQ_VS_NOT_FOUND });
    }

    return defined wantarray && AnyEvent::Util::guard { undef $guard };
}

sub delete_vs {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $vs      = shift; # `editedInterface` and `editedChannel`
    my %arg     = @_;
    my $request = { Operation   => 9,
                    Method      => 'POST',
                    QueryString => 'iAction=3&iType=4',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid },
                    Parameters  => $vs };

    unless (length $vs->{editedInterface} && length $vs->{editedChannel}) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                            Detail => "Not all mandatory arguments provided" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;
        # Check JSON for StatusText and set error (if any).
        _try_to_populate_error $json, $hdr, 'delete_vs', 'delete a VS';
        return unless $hdr->{Success};

        my $vips = _get_vips_from_json %$json; # Can be undefined.
        $_[0] = $vips;
        ()
    };

    return _request($request, %arg, $cb);
}

sub delete_vs_by_specs {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my @specs   = splice @_, 0, 3; # Only: IP, subnet, port (duplicate trace).
    my %arg     = @_;

    $_ = "$_" for @specs; # Stringify.
    my ($ipAddr, $subnetMask, $port) = @specs;

    my $empty = 0;
    $empty += !length $ipAddr;
    $empty += !length $subnetMask;
    $empty += !length $port;

    unless ($empty == 3 || $empty == 0) {
        return $cb->(undef, { Code   => API_REQ_INPUT_INVALID,
                            Detail => "Not all mandatory arguments provided " .
                                      "or all must be undefined to remove " .
                                      "empty VS" });
    }

    # Send multiple requests one after one. TODO: Use promises.
    my $guard  = 1;
    my $new_cb = _cb_nowrap sub {
        $guard &&= 1 or return;
        my ($found, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        AE::log debug => "Delete virtual service by interface and channel ID";
        my $vs;
        $vs->{editedInterface} = $found->{InterfaceID};
        $vs->{editedChannel}   = $found->{ChannelID};

        # Second, delete VS by IDs
        $guard = delete_vs($creds, $vs, %arg, $cb);
        ()
    };

    # First, find virtual service and get its interface and channel ID
    $guard = get_vs($creds, undef, $ipAddr, $subnetMask, $port,
                     undef, undef, undef, undef, %arg, $new_cb);

    return defined wantarray && AnyEvent::Util::guard { undef $guard };
}

sub change_basic_settings {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $vs      = shift; # See enable_ssl_vs_by_specs() for example.
    my %arg     = @_;
    my $request = { Operation   => 9,
                    Method      => 'POST',
                    QueryString  => 'iAction=2&iType=3',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid },
                    Parameters  => $vs };

    unless ($vs->$_isa('Edge::ClientAPI::Object::VS') || ref $vs eq 'HASH') {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                        Detail => "Incorrect 'vs' value in change_basic_settings()" });
    }

    unless (length $vs->{editedInterface} && length $vs->{editedChannel}) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                        Detail => "No edited interface or channel values " .
                                  "in change_basic_settings()" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;
        # Check JSON for StatusText and set error (if any).
        _try_to_populate_error $json, $hdr, 'change_basic_settings', 'enable SSL';
        return unless $hdr->{Success};

        my $vips = _get_vips_from_json %$json; # Can be undefined.
        if (defined $vips) {
            my $updated = _find_vs_by_ids(@$vips,
                                $vs->{editedInterface}, $vs->{editedChannel});
            if ($updated) {
                # Success.
                AE::log info => "Basic settings have been changes";
                $_[0] = $updated;
                return;
            }
        }
        ()
    };

    AE::log info => "Change basic settings...";
    return _request($request, %arg, $cb);
}

sub enable_ssl_vs_by_specs {
    my $cb        = _cb_wrap pop;
    my $creds     = shift;
    my $cert_name = shift;
    my @specs     = splice @_, 0, 3; # Only: IP, subnet, port (duplicate trace).
    my %arg       = @_;

    $_ = "$_" for @specs; # Stringify.
    my ($ipAddr, $subnetMask, $port) = @specs;

    unless (length $ipAddr && length $subnetMask && length $port) {
        return $cb->(undef, { Code => API_REQ_INPUT_INVALID,
                            Detail => "Not all mandatory arguments provided" });
    }

    unless (length $cert_name) {
        return $cb->(undef, { Code => API_REQ_INPUT_INVALID,
                            Detail => "No SSL certificate name" });
    }

    # Send multiple requests one after one. TODO: Use promises.
    my $guard  = 1;
    my $new_cb = _cb_nowrap sub {
        $guard &&= 1 or return;
        my ($found, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        AE::log debug => "Enable SSL for VS by interface %s and channel ID %s",
                         $found->{InterfaceID}, $found->{ChannelID};
        AE::log trace => "VS info: %s", Dumper+$found;

        my $vs;

        # TODO: Doesn't change `sslCertificate` if the below is sent to
        # /POST/9?iAction=2&iType=6 as follows:
        #$vs->{editedInterface}           = $found->{InterfaceID};
        #$vs->{editedChannel}             = $found->{ChannelID};
        #$vs->{CheckChannelKey}           = $found->{ChannelKey};
        #$vs->{CipherName}                = $found->{CipherName};
        #$vs->{SNIDefaultCertificateName} = $found->{SNIDefaultCertificateName};
        #$vs->{sslCertificate}            = $cert_name;
        #$vs->{sslClientCertificate}      = $found->{sslClientCertificate};
        #$vs->{sslRenegotiation}          = $found->{sslRenegotiation};
        #$vs->{sslResumption}             = $found->{sslResumption};

        # Change `sslCertificate` if the below is sent to
        # /POST/9?iAction=2&iType=3
        $vs->{acceleration}         = $found->{acceleration};
        $vs->{cachingRule}          = $found->{cachingRule};
        $vs->{editedInterface}      = $found->{InterfaceID};
        $vs->{editedChannel}        = $found->{ChannelID};
        $vs->{loadBalancingPolicy}  = $found->{loadBalancingPolicy};
        $vs->{serverMonitoring}     = $found->{serverMonitoring};
        $vs->{sslCertificate}       = $cert_name;
        $vs->{sslClientCertificate} = $found->{sslClientCertificate};

        AE::log trace => "SSL VS info in use: %s", Dumper+$vs;

        # Second, enable SSL cert for VS by IDs
        $guard = change_basic_settings($creds, $vs, %arg, $cb);
        ()
    };

    # First, find virtual service and get its interface and channel ID
    $guard = get_vs($creds, undef, $ipAddr, $subnetMask, $port,
                    undef, undef, undef, undef, %arg, $new_cb);

    return defined wantarray && AnyEvent::Util::guard { undef $guard };
}

sub disable_ssl_vs_by_specs {
    my $cb        = _cb_wrap pop;
    my $creds     = shift;
    my @specs     = splice @_, 0, 3; # Only: IP, subnet, port (duplicate trace).
    return enable_ssl_vs_by_specs($creds, "No SSL", @specs, $cb, @_);
}

sub create_rs_empty {
    my $cb         = _cb_wrap pop;
    my $creds      = shift;
    my $iface_id   = shift;
    my $channel_id = shift;
    my %arg        = @_;
    my $options    = +{};
    my $request    = { Operation   => 9,
                       Method      => 'POST',
                       QueryString => 'iAction=3&iType=3',
                       InputType   => 'json',
                       OutputType  => 'json',
                       Host        => $creds->host,
                       Port        => $creds->port,
                       Cookie      => { GUID  => $creds->guid },
                       Parameters  => $options };

    unless (length $iface_id) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                     Detail => "Invalid interface ID in create_rs_empty()" });
    }
    unless (length $channel_id) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                     Detail => "Invalid channel ID in create_rs_empty()" });
    }

    $options->{editedInterface} = $iface_id;
    $options->{editedChannel}   = $channel_id;

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;
        # Check JSON for StatusText and set error (if any).
        _try_to_populate_error $json, $hdr, 'create_rs_empty', 'update a RS';
        return unless $hdr->{Success};

        my $vips = _get_vips_from_json %$json; # Can be undefined.
        if (defined $vips) {
            my $updated = _find_vs_by_ids(@$vips, $iface_id, $channel_id);
            if ($updated) {
                # Success. Return only updated VS.
                AE::log info => 'Empty slot for real server has been created';
                $_[0] = $updated;
                return;
            }
        }

        $hdr->{Success} = 0;
        $hdr->{Detail}  = "Unable to find the updated VS in create_rs_empty()";
        ()
    };

    AE::log info => 'Create empty slot for real server...';
    return _request($request, %arg, $cb);
}

sub update_rs {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $vs      = shift; # See init_rs_multi() for details.
    my %arg     = @_;
    my $request = { Operation   => 9,
                    Method      => 'POST',
                    QueryString => 'iAction=2&iType=2',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid },
                    Parameters  => $vs };

    unless (($vs->$_isa('Edge::ClientAPI::Object::VS') || ref $vs eq 'HASH') &&
            length $vs->{editedInterface} &&
            length $vs->{editedChannel}) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                        Detail => "Incorrect 'vs' value in update_rs()" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;
        _try_to_populate_error $json, $hdr, 'update_rs', 'update a RS';

        my $vips = _get_vips_from_json %$json; # Can be undefined.
        if (defined $vips) {
            my $updated = _find_vs_by_ids(@$vips, $vs->{editedInterface},
                                                  $vs->{editedChannel});
            if ($updated) {
                # Success. Return only updated VS.
                AE::log info => "RS with interface ID %s and channel key %s " .
                                "has been updated", $vs->{editedInterface},
                                                    $vs->{editedChannel};

                $_[0] = $updated; # Blessed to ::VS object
                return;
            }
        }

        $hdr->{Success} = 0;
        $hdr->{Detail}  = "Unable to find the updated VS in update_rs()";
        ()
    };

    AE::log info => "Update RS with interface ID %s and channel key %s...",
                    $vs->{editedInterface}, $vs->{editedChannel};

    return _request($request, %arg, $cb);
}

sub init_rs_multi {
    my $cb    = _cb_wrap pop;
    my $creds = shift;
    my $vs    = shift; # Virtual Service hashref (not modified).
    my $rss   = shift;
    my %arg   = @_;

    unless ($vs->$_isa('Edge::ClientAPI::Object::VS') || ref $vs eq 'HASH') {
        return $cb->(undef, { Code => API_REQ_INPUT_INVALID,
                       Detail => "Incorrect 'vs' value in init_rs_multi()" });
    }

    unless (ref $rss eq 'ARRAY') {
        return $cb->(undef, { Code => API_REQ_INPUT_INVALID,
                            Detail => "Real Server reference is not array." });
    }

    for (@$rss) {
        # `weight` is optional.
        unless (length $_->{addr} &&
                length $_->{port}
                #length $_->{notes} &&
                #length $_->{ServerId}
        ) {
            return $cb->(undef, { Code => API_REQ_INPUT_INVALID,
                                Detail => "Invalid Real Server element." });
        }

        # Stringify.
        for my $k (qw(addr port notes ServerId weight)) {
            $_->{$k} = "" . $_->{$k};
        }
    }

    my $new_vs = $vs;
    # RS initialization means that there's cID == 0,
    # a newly created "empty" Real Server data,
    # because first empty CS is created automatically when
    # creating a new VS.
    my $cId    = int($arg{cId} || 0);

    AE::log info => "Start initializing multiple RS...";

    my @state;
    push @state, scalar AnyEvent::Tools::async_foreach
        $rss,
        sub {
            return unless @state;
            my ($guard, $rs, $index, $first_flag, $last_flag) = @_;
            AE::log debug => "Process RS with index %d...", $index;
            AE::log trace => "RS element: %s", Dumper+$rs;
            push @state, $guard;

            my @css;
            if (ref $new_vs->{contentServer} eq 'HASH' &&
                ref $new_vs->{contentServer}{CServerId} eq 'ARRAY') {
                @css = ($new_vs->{contentServer}{CServerId});
            }

            my $empty_cs;
            if (@css > 0) {
                for my $cs_ref (@css) {
                    next unless @$cs_ref;
                    for my $tmp_cs (@$cs_ref) {
                        AE::log trace => "tmp_cs is %s", Dumper+$tmp_cs;
                        if ($tmp_cs->{cId} == $cId) {
                            $empty_cs = $tmp_cs;
                            last;
                        }
                    }
                }
            }

            unless (defined $empty_cs) {
                @state = ();
                return $cb->(undef, { Code   => API_REQ_VS_CSERVER_ID,
                                      Detail => "CServerId not found" });
            }

            # Fill in actual data for a CS.
            my $cs;
            $cs->{editedInterface} = $new_vs->{InterfaceID};
            $cs->{editedChannel}   = $new_vs->{ChannelID};
            $cs->{serverKey}       = $empty_cs->{serverKey};
            $cs->{cId}             = $empty_cs->{cId};
            $cs->{CSActivity}      = "1";
            $cs->{CSIPAddr}        = $rs->{addr};
            $cs->{CSPort}          = $rs->{port};
            $cs->{CSNotes}         = $rs->{notes};
            $cs->{ServerId}        = $rs->{ServerId};
            $cs->{WeightFactor}    = length $rs->{weight}
                                   ? $rs->{weight}
                                   : "100";
            $cId++;

            my $new_cb = sub {
                return unless @state;
                my ($vs, $hdr) = @_;
                unless ($hdr->{Success}) {
                    $cb->(@_);
                    return;
                }

                pop @state;
                if ($last_flag) {
                    # No more $rs to init, so destroy $guard.
                    pop @state;
                    $cb->($vs, $hdr);
                    return;
                }

                # Create empty RS.
                my $new_cb = sub {
                    return unless @state;
                    my $hdr;
                    ($new_vs, $hdr) = @_; # Update $new_vs.
                    unless ($hdr->{Success}) {
                        $cb->(@_);
                        return;
                    }

                    pop @state;
                    pop @state; # Destroy $guard, for the next iteration.
                    ()
                };

                AE::log info => "Create empty RS...";
                push @state, scalar create_rs_empty(
                    $creds, $new_vs->{InterfaceID}, $new_vs->{ChannelID},
                    %arg, $new_cb);
            };

            AE::log info => "Add RS %s:%s...", $cs->{CSIPAddr}, $cs->{CSPort};
            push @state, scalar update_rs($creds, $cs, %arg, $new_cb);
            ()
        },
        sub {
            AE::log info => "Multi RS initialization has been completed.";
            ()
        }
    ;

    return defined wantarray && AnyEvent::Util::guard { @state = () };
}

sub init_rs_multi_by_specs {
    my $cb    = _cb_wrap pop;
    my $creds = shift;
    my $rss   = shift;
    my @specs = splice @_, 0, 3; # Only: IP, subnet, port (duplicate trace).
    my %arg   = @_;

    AE::log trace => "init_rs_multi_by_specs RSS: %s",   Dumper+$rss;
    AE::log trace => "init_rs_multi_by_specs specs: %s", Dumper+\@specs;

    $_ = "$_" for @specs; # Stringify.
    my ($ipAddr, $subnetMask, $port) = @specs;

    unless (ref $rss eq 'ARRAY') {
        return $cb->(undef, { Code   => API_REQ_INPUT_INVALID,
                              Detail => "Real Server reference is not array." });
    }

    unless (length $ipAddr && length $subnetMask && length $port) {
        return $cb->(undef, { Code   => API_REQ_INPUT_INVALID,
                            Detail => "Not all mandatory arguments provided" });
    }

    # Send multiple requests one after one. TODO: Use promises.
    my $guard  = 1;
    my $new_cb = _cb_nowrap sub {
        $guard &&= 1 or return;
        my ($found, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        # Second, update multiple Remote Servers for the Virtual Service.
        $guard = init_rs_multi($creds, $found, $rss, %arg, $cb);
        ()
    };

    # First, find virtual service and get its interface and channel ID
    $guard = get_vs($creds, undef, $ipAddr, $subnetMask, $port,
                    undef, undef, undef, undef, %arg, $new_cb);

    return defined wantarray && AnyEvent::Util::guard { undef $guard };
}

sub upsert_rs {
    my $cb    = _cb_wrap pop;
    my $creds = shift;
    my $rs    = shift;
    my @specs = splice @_, 0, 3; # Only: IP, subnet, port (duplicate trace).
    my %arg   = @_;

    AE::log trace => "upsert_rs RS: %s",   Dumper+$rs;
    AE::log trace => "upsert_rs specs: %s", Dumper+\@specs;

    $_ = "$_" for @specs; # Stringify.
    my ($ipAddr, $subnetMask, $port) = @specs;

    unless (ref $rs eq 'HASH') {
        return $cb->(undef, { Code   => API_REQ_INPUT_INVALID,
                              Detail => "Real Server reference is not hash" });
    }

    unless (length $ipAddr && length $subnetMask && length $port) {
        return $cb->(undef, { Code   => API_REQ_INPUT_INVALID,
                            Detail => "Not all mandatory arguments provided" });
    }

    my $guard  = 1;
    my $new_cb = _cb_nowrap sub {
        $guard &&= 1 or return;
        my ($found, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        my ($cs, $empty_cs_id);
        my $css = $found->{contentServer}{CServerId};
        if (ref $css eq 'ARRAY') {
            for (@$css) {
                if ($_->{CSIPAddr} eq $rs->{addr} &&
                    $_->{CSPort}   eq $rs->{port}) {
                    $cs = $_;
                }
                unless (length $_->{CSIPAddr} && length $_->{CSPort}) {
                    $empty_cs_id = $_->{cId};
                }
            }
        }

        if ($cs) {
            # Remote Server is found.
            $hdr->{RS_Found} = 1;
            $cb->(@_);
            return;
        }

        # Remote Server is not found.
        unless (length $empty_cs_id) {
            AE::log debug => "Empty RS is not found.";

            # Create empty RS.
            my $new_cb = sub {
                $guard &&= 1 or return;
                my $hdr;
                ($found, $hdr) = @_; # Update $found.

                unless ($hdr->{Success}) {
                    $cb->(@_);
                    return;
                }

                my $css = $found->{contentServer}{CServerId};
                if (ref $css eq 'ARRAY') {
                    for (@$css) {
                        unless (length $_->{CSIPAddr} && length $_->{CSPort}) {
                            $empty_cs_id = $_->{cId};
                        }
                    }
                }

                unless (length $empty_cs_id) {
                    return $cb->(undef, { Code   => API_REQ_VS_CSERVER_ID,
                                          Detail => "Empty RS not found" });
                }

                AE::log debug => "Empty RS created (cId is %s)", $empty_cs_id;
                AE::log debug => "Add RS...";

                $arg{cId} = $empty_cs_id;
                $guard    = init_rs_multi($creds, $found, [ $rs ], %arg, $cb);
                ()
            };

            $guard = create_rs_empty(
                    $creds, $found->{InterfaceID}, $found->{ChannelID},
                    %arg, $new_cb);
            return;
        }

        AE::log debug => "Empty RS found (cId is %s)", $empty_cs_id;
        AE::log debug => "Add RS...";

        $arg{cId} = $empty_cs_id;
        $guard    = init_rs_multi($creds, $found, [ $rs ], %arg, $cb);
        ()
    };

    # First, find virtual service and get its interface and channel ID
    $guard = get_vs($creds, undef, $ipAddr, $subnetMask, $port,
                    undef, undef, undef, undef, %arg, $new_cb);

    return defined wantarray && AnyEvent::Util::guard { undef $guard };
}

sub remove_rs_by_specs {
    my $cb    = _cb_wrap pop;
    my $creds = shift;
    my $rs    = shift; # e.g. { addr => "1.1.1.3", port => 8080, ... }
    my @specs = splice @_, 0, 3; # Only: IP, subnet, port
    my %arg   = @_;

    AE::log trace => "remove_rs RS: %s",   Dumper+$rs;
    AE::log trace => "remove_rs specs: %s", Dumper+\@specs;

    $_ = "$_" for @specs; # Stringify.
    my ($ipAddr, $subnetMask, $port) = @specs;

    unless (ref $rs eq 'HASH') {
        return $cb->(undef, { Code   => API_REQ_INPUT_INVALID,
                              Detail => "Real Server reference is not hash" });
    }

    unless (length $ipAddr && length $subnetMask && length $port) {
        return $cb->(undef, { Code   => API_REQ_INPUT_INVALID,
                            Detail => "Not all mandatory arguments provided" });
    }

    my $guard  = 1;
    my $new_cb = _cb_nowrap sub {
        $guard &&= 1 or return;
        my ($found, $hdr) = @_;
        unless ($hdr->{Success}) {
            $cb->(@_);
            return;
        }

        my $cs;
        my $css = $found->{contentServer}{CServerId};
        if (ref $css eq 'ARRAY') {
            for (@$css) {
                if ($_->{CSIPAddr} eq $rs->{addr} &&
                    $_->{CSPort}   eq $rs->{port}) {
                    $cs = $_;
                }
            }
        }

        unless ($cs) {
            # Remote Server is found. Consider operation has been completed.
            $hdr->{RS_Found} = 0;
            $cb->(@_);
            return;
        }

        my $cId = $cs->{cId};
        my %cs  = (
            editedInterface => $found->{InterfaceID},
            editedChannel   => $found->{ChannelID},
            cId             => $cId,
        );

        $guard = remove_rs($creds, \%cs, $cb);
        ()
    };

    # First, find virtual service and get its interface and channel ID
    $guard = get_vs($creds, undef, $ipAddr, $subnetMask, $port,
                    undef, undef, undef, undef, %arg, $new_cb);

    return defined wantarray && AnyEvent::Util::guard { undef $guard };
}

sub remove_rs {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $cs      = shift; # e.g. {"editedInterface":"0","editedChannel":"0","cId":"0"}
    my %arg     = @_;
    my $request = { Operation   => 9,
                    Method      => 'POST',
                    QueryString => 'iAction=3&iType=5',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid },
                    Parameters  => $cs };

    unless (ref $cs eq 'HASH' &&
            length $cs->{editedInterface} &&
            length $cs->{editedChannel}   &&
            length $cs->{cId}) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                        Detail => "Incorrect 'cs' value in remove_rs()" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;

        _try_to_populate_error $json, $hdr, 'remove_rs', 'remove a RS';

        my $vips = _get_vips_from_json %$json; # Can be undefined.
        if (defined $vips) {
            my $updated = _find_vs_by_ids(@$vips, $cs->{editedInterface},
                                                  $cs->{editedChannel});
            if ($updated) {
                # Success. Return only updated VS.
                $_[0] = $updated;
                return;
            }
        }

        $hdr->{Success} = 0;
        $hdr->{Detail}  = "Unable to find the updated VS in remove_rs()";
        ()
    };

    return _request($request, %arg, $cb);
}

1;
