package Edge::ClientAPI::Request;
use common::sense;
#use AnyEvent 5.0  ();
#use AnyEvent::Log ();
#use AnyEvent::HTTP;
#use URI;
#use JSON::XS;
use Try::Tiny;
use Data::Dumper;
use Safe::Isa;
use Edge::ClientAPI;
use Edge::ClientAPI::Request::_Base;
use Edge::ClientAPI::Request::IPServicesApi;
use Edge::ClientAPI::Request::FlightPATH;
use Edge::ClientAPI::E
    API_REQ_CERT_NOT_FOUND => [ 5270, "Certficate is not found" ],
;

# API methods: names be added to be used from Edge::ClientAPI::API class
our @METHODS = qw(
    authorize
    download_conf
    get_flight_path_ids
    upload_flight_path_config
    remove_ssl_cert
    import_ssl_cert
    export_ssl_cert
    get_certificate
    get_all_certificates
    get_ssl_cert_details

    get_all_vs
    get_vs
    create_empty_vs
    create_vs
    update_vs
    delete_vs
    delete_vs_by_specs
    change_basic_settings
    enable_ssl_vs_by_specs
    disable_ssl_vs_by_specs
    update_rs
    upsert_rs
    init_rs_multi
    init_rs_multi_by_specs
    create_rs_empty
    remove_rs_by_specs
    remove_rs

    fake_request
    dummy_test

    create_fp_custom_forward
    remove_fp_custom_forward
    apply_fp_by_name
    unapply_fp_by_name
);

# ----------------------------------------------------------------------
# Public functions for API
# ----------------------------------------------------------------------
sub authorize {
    my $cb       = _cb_wrap pop;
    my $creds    = shift;
    my $username = $creds->user;
    my $password = $creds->pass;
    my %arg      = @_;
    my $request  = { Operation  => 32,
                     Host       => $creds->host,
                     Port       => $creds->port,
                     Method     => 'POST',
                     InputType  => 'json',
                     OutputType => 'json',
                     Parameters => { $username => $password } };

    unless (is_valid_username $username) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid username" });
    }

    unless (is_valid_password $password) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid password" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;
        return unless $hdr->{Code} == 0; # Error is in `Code` & `Detail`.

        # e.g. {"LoginStatus":"OK","UserName":"admin","GUID":"efdf..."}

        unless (length $json->{LoginStatus}) {
            $hdr->{Code}   = API_REQ_OUTPUT_INVALID;
            $hdr->{Detail} = "No `LoginStatus` in response";
            return;
        }

        unless ($json->{LoginStatus} eq 'OK') {
            $hdr->{Code}   = API_REQ_AUTH_INVALID;
            $hdr->{Detail} = "Invalid credentials";
            return;
        }

        unless ($json->{UserName} eq $username) {
            $hdr->{Code}   = API_REQ_OUTPUT_INVALID;
            $hdr->{Detail} = "Invalid `UserName` in response";
            return;

        }

        unless (is_valid_guid $json->{GUID}) {
            $hdr->{Code}   = API_REQ_OUTPUT_INVALID;
            $hdr->{Detail} = "No `GUID` in response";
            return;
        }

        $hdr->{Success} = 1;
        $_[0] = $json->{GUID}; # Return valid GUID as successful result.
        ()
    };

    AE::log debug => "Send auth request for user '%s'...", $username;
    return _request($request, %arg, $cb);
}

sub download_conf {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my %arg     = @_;
    my $request = { Operation  => 26,
                    Method     => 'GET',
                    InputType  => 'form',
                    OutputType => 'plain|json',
                    Host       => $creds->host,
                    Port       => $creds->port,
                    Cookie     => { GUID     => $creds->guid  },
                    Parameters => { download => 'conf' } };


    $arg{on_success} = sub {
        my ($json_or_plain, $hdr) = @_;

        unless (ref $json_or_plain) {
            # Response is not JSON. We got config INI file.
        } else {
            # Response is JSON. Error is expected.
            $hdr->{Success} = 0;
            $hdr->{Detail}  = length $json_or_plain->{DownloadStatus}
                            ? $json_or_plain->{DownloadStatus}
                            : "Unknown error";
        }

        ()
    };



    AE::log debug => "Download ADC config...";
    return _request($request, %arg, $cb);
}

sub get_flight_path_ids {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my %arg     = @_;
    my $request = { Operation  => 26,
                    Method     => 'GET',
                    InputType  => 'form',
                    OutputType => 'plain',
                    Host       => $creds->host,
                    Port       => $creds->port,
                    Cookie     => { GUID     => $creds->guid  },
                    Parameters => { download => 'conf' } };

    $arg{on_success} = sub {
        my ($plain, $hdr) = @_;
        # TODO: Implement as needed. This is a demo that puts config
        # sections to flightPATH IDs for output.
        my @ids;
        for my $line (split /\n/, $plain) {
            if ($line =~ /^\[    ([^\]]+)    \]/x) {
                # e.g. `jetnexusdaemon-Path-8`, `jetnexusdaemon-Cache`, etc.
                my $section = $1;
                next unless $section =~ /^jetnexusdaemon-Path-(\d+)$/;
                push @ids, {
                    id    => $1,
                    label => $section,
                };
            }
        }

        $_[0] = \@ids; # Set new value in output.
        ()
    };

    AE::log debug => "Get all flightPATH IDs...";
    return _request($request, %arg, $cb);
}

sub upload_flight_path_config {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $config  = shift; # Config data, a plain text
    my %arg     = @_;

    my $request = { Operation   => 26,
                    Method      => 'POST',
                    InputType   => 'form',
                    OutputType  => 'json',
                    QueryString => 'iAction=1&iType=1&send=conf',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID => $creds->guid   },
                    Files       => { data => { filename     => 'config.dat',
                                               content      => $config,
                                               content_type => 'application/octet-stream' } },
                    Parameters => +{} };

    unless ($config =~ /^\#\!jetpack/) {
        # Without #!jetpack the config won't be accepted.
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid flightPATH config (doesn't begin with #!jetpack)" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;

        if (defined $json->{StatusImage} &&
            $json->{StatusText} ne 'Configuration updated successfully' &&
            $json->{StatusText} ne 'Filetype=config') {
            $hdr->{Success} = 0;
            $hdr->{Detail}  = "ALB API request to upload ALB config failed " .
                              "failed in upload_flight_path_config(): " .
                              "'$json->{StatusText}'";

            return;
        }
        ()
    };

    AE::log debug => "Upload flightPATH config...";
    return _request($request, %arg, $cb);
}

sub remove_ssl_cert {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $name    = shift; # Certificate name.
    my %arg     = @_;
    my $options = +{};
    my $request = { Operation   => 19,
                    Method      => 'POST',
                    QueryString => 'iAction=2&iType=4',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID     => $creds->guid  },
                    Parameters  => $options };

    $options->{CertificateName} = $name;
    $options->{CetificateName}  = $name;

    unless (!ref $name && length $name) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid certificate name" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;

        if (defined $json->{StatusImage} &&
            $json->{StatusText} ne 'Your changes have been applied' &&
            $json->{StatusText} ne 'Certificate has been deleted.') {
            $hdr->{Success} = 0;
            $hdr->{Detail}  = "ALB API request to remove SSL certificate " .
                              "failed in remove_ssl_cert(): " .
                              "'$json->{StatusText}'";

            return;
        }
        ()
    };

    AE::log debug => "Remove certificate %s...", $name;
    return _request($request, %arg, $cb);
}

sub get_all_certificates {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my %arg     = @_;

    my $request = { Operation  => 19,
                    Method     => 'GET',
                    InputType  => 'form',
                    OutputType => 'json',
                    Host       => $creds->host,
                    Port       => $creds->port,
                    Cookie     => { GUID  => $creds->guid   },
                    Parameters => +{} };

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;

        if (defined $json->{StatusImage} &&
            $json->{StatusText} ne 'Your changes have been applied' &&
            $json->{StatusText} ne 'get') {
            $hdr->{Success} = 0;
            $hdr->{Detail}  = "ALB API request to get SSL certificate " .
                              "status failed in get_all_certificates(): " .
                              "'$json->{StatusText}'";
            return;
        }

        my $comboName = 'CertificateManageCombo';

        unless (defined $json->{$comboName} &&
            defined $json->{$comboName}{options} &&
            defined $json->{$comboName}{options}{option} &&
            @{$json->{$comboName}{options}{option}}) {

            $_[0] = []; # Return empty array with certificates.
            return;
        }

        $_[0] = $json->{$comboName}{options}{option}; # Non-empty arrayref.
        ()
    };

    return _request($request, %arg, $cb);
}

sub import_ssl_cert {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $name    = shift; # Certificate name.
    my $binary  = shift; # Certificate PKCS12 binary data.
    my $pwd     = shift; # Certificate password.
    my %arg     = @_;
    my $options = +{};
    my $request = { Operation   => 19,
                    Method      => 'POST',
                    QueryString => 'send=sslimport&iAction=3&iType=1',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid },
                    Files       => { SslCertificatesImportUploadText => {
                                        filename     => 'export.pfx',
                                        content      => $binary,
                                        content_type => 'application/octet-stream' } },
                    Parameters  => $options };

    $options->{SslCertificatesImportCertificateNameText} = $name;
    $options->{SslCertificatesImportPasswordText}        = $pwd;

    unless (!ref $name && length $name) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid certificate name" });
    }

    $arg{on_success} = sub {
        my ($json, $hdr) = @_;

        if (defined $json->{StatusImage} &&
            $json->{StatusText} ne 'Your changes have been applied' &&
            $json->{StatusText} ne 'Certificate has been successfully imported') {

            $json->{StatusText} ||= 'unknown error';
            $hdr->{Success} = 0;
            $hdr->{Detail}  = "ALB API request to import SSL certificate " .
                              "failed in import_ssl_cert(): " .
                              "'$json->{StatusText}'";
        }

        ()
    };

    return _request($request, %arg, $cb);
}

sub export_ssl_cert {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $name    = shift; # Certificate name.
    my $pwd     = shift; # Certificate password.
    my %arg     = @_;

    my $options = +{};
    my $request = { Operation   => 19,
                    Method      => 'GET',
                    InputType   => 'form',
                    OutputType  => 'plain',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid   },
                    Parameters  => $options };

    $options->{download} = 'sslexport';
    $options->{iAction}  = 4;
    $options->{name}     = $name;
    $options->{pas}      = $pwd;

    return _request($request, %arg, $cb);
}

sub get_ssl_cert_details {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $name    = shift; # Certificate name.
    my %arg     = @_;

    my $options = +{};
    my $request = { Operation   => 19,
                    Method      => 'POST',
                    QueryString => 'iAction=2&iType=1&show=cert',
                    InputType   => 'json',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid   },
                    Parameters  => $options };

    $options->{CertificateName} = $name;
    $options->{CetificateName}  = $name;

    unless (!ref $name && length $name) {
        return $cb->(undef, { %$request, Code   => API_REQ_INPUT_INVALID,
                                         Detail => "Invalid certificate name" });
    }

    #2021-06-22 18:01:11 +0400 +     "Organization": "",
    #2021-06-22 18:01:11 +0400 +     "StateProvince": "",
    #2021-06-22 18:01:11 +0400 +     "Country": "",
    #...
    #2021-06-22 18:01:11 +0400 +     "DomainName": "example.com",
    #2021-06-22 18:01:11 +0400 +     "KeyLength": "2048",
    #2021-06-22 18:01:11 +0400 +     "Expires": " Sep 20 11:39:46 2021 GMT"
    $arg{on_success} = sub {
        my ($json, $hdr) = @_;

        if (defined $json->{StatusImage} &&
            $json->{StatusText} ne 'Your changes have been applied' &&
            $json->{StatusText} ne 'Certificate has been deleted.') {

            $json->{StatusText} ||= 'unknown error';
            $hdr->{Success} = 0;
            $hdr->{Detail}  = "ALB API request to get SSL certificate " .
                              "details failed in get_ssl_cert_details(): " .
                              "'$json->{StatusText}'";
            return;
        }

        # NOTE: If certificate is not found, JSON with CertificateName is
        # defined.
        unless (defined $json->{CertificateName}) {
            $hdr->{Success} = 0;
            $hdr->{Detail}  = "ALB API request to get SSL certificate " .
                              "details failed in get_ssl_cert_details(): " .
                              "'$json->{StatusText}'";
            return;
        }

        unless (length $json->{KeyLength}) {
            # Rely on key length: if it is defined, then cert exists.
            my $e = e40 API_REQ_CERT_NOT_FOUND;
            $hdr->{Success} = 0;
            $hdr->{Code}    = int $e;
            $hdr->{Detail}  = "" . $e;
            return;
        }

        ()
    };

    return _request($request, %arg, $cb);
}

sub fake_request {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my %arg     = @_;
    my $request = { Operation   => 28,
                    Method      => 'GET',
                    InputType   => 'form',
                    OutputType  => 'json',
                    Host        => $creds->host,
                    Port        => $creds->port,
                    Cookie      => { GUID  => $creds->guid   },
                    Parameters  => +{} };

    return _request($request, %arg, $cb);
}

# This request has no sense in production. Put here any values you like to test.
# And then use it freely in your test-driven development.
sub dummy_test {
    my $cb      = _cb_wrap pop;
    my $creds   = shift;
    my $binary  = shift; # Certificate PKCS12 binary data.
    my %arg     = @_;

    # TODO: set correct values
    my $request = { Operation  => 19,
                    Method     => 'GET',
                    InputType  => 'form',
                    OutputType => 'plain',
                    Host       => $creds->host,
                    Port       => $creds->port,
                    Cookie     => { GUID  => $creds->guid   },
#                    Parameters => { cert  => $binary } 
    };

    return _request($request, %arg, $cb);
}

1;
