package Edge::ClientAPI::Data;
use common::sense;
use boolean;
use Data::Dumper;
use Carp;
use Try::Tiny;
use Scalar::Util;
use Safe::Isa;
use AnyEvent::Socket ();
use Edge::ClientAPI::E
    EDGE_DATA_PORT_BAD  => [ 8004, "Invalid port"               ],
    EDGE_DATA_FP_ID_BAD => [ 8005, "Invalid flightPATH ID"      ],
    EDGE_DATA_IPV4_BAD  => [ 8006, "Invalid IPv4 address"       ],
    EDGE_DATA_IPV6_BAD  => [ 8007, "Invalid IPv6 address"       ],
    EDGE_DATA_IP_BAD    => [ 8008, "Invalid IP address"         ],
    EDGE_DATA_GUID_BAD  => [ 8009, "Invalid GUID"               ],
    EDGE_DATA_PWD_SHORT => [ 8010, "Password must have 6 or more characters" ],
    EDGE_DATA_PWD_EMPTY => [ 8011, "No password" ],
    EDGE_DATA_PWD_LONG  => [ 8012, "Password is too long." ],

    EDGE_DATA_DOMAIN_EMPTY  => [ 8000, "No domain name entered" ],
    EDGE_DATA_DOMAIN_BAD    => [ 8001, "Invalid domain name" ],
    EDGE_DATA_DOMAIN_NO_DOT => [ 8002, "Domain name needs at least one dot" ],
    EDGE_DATA_DOMAIN_IDN    => [ 8003, "International domain name is not accepted. Represent it using punycode." ],

    EDGE_DATA_CERT_NAME_BAD   => [ 8013, "Certificate name doesn't contain any meaningful characters" ],
    EDGE_DATA_CERT_NAME_EMPTY => [ 8014, "Certificate name is empty" ],


    EDGE_DATA_CN_SERVER_NAME_EMPTY  => [ 8025, "No certificate common name to represent the server name entered" ],
    EDGE_DATA_CN_SERVER_NAME_BAD    => [ 8026, "Invalid common name to represent the server name" ],
    EDGE_DATA_CN_SERVER_NAME_NO_DOT => [ 8027, "Common name to represent the server name needs at least one dot" ],
    EDGE_DATA_CN_SERVER_NAME_IDN    => [ 8028, "Common name cannot be international domain name. Represent it using punycode." ],
    EDGE_DATA_CN_SERVER_NAME_BAD_WCARD => [ 8029, "Invalid common name to represent wildcard server names" ],
;

# ------------------------------------------------------------------------------
# Public functions (data validators)
# ------------------------------------------------------------------------------
sub validate_port($;$) {
    my ($port, $arg) = @_;
    if ($port =~ /^\d+$/ && $port > 0 && $port <= 0xFFFF) {
        #$_[0] = int $port;
        return 0;
    }

    my $e = e40 EDGE_DATA_PORT_BAD;
    $arg eq '-nodie' ? return $e : die $e;
}

sub validate_fp_id($;$) {
    my ($flight_path_id, $arg) = @_;
    if ($flight_path_id =~ /^[\w\-\.]+$/) {
        return 0;
    }

    my $e = e40 EDGE_DATA_FP_ID_BAD;
    $arg eq '-nodie' ? return $e : die $e;
}

sub validate_ipv4($;$) {
    my $ipn = AnyEvent::Socket::parse_ipv4($_[0]);
    if (defined $ipn && $_[0] =~ /^\d+\.\d+\.\d+\.\d+$/) {
        return 0;
    }

    my $e = e40 EDGE_DATA_IPV4_BAD;
    $_[1] eq '-nodie' ? return $e : die $e;
}

sub validate_ipv6($;$) {
    my $ipn = AnyEvent::Socket::parse_ipv6($_[0]);
    if (defined $ipn) {
        return 0;
    }

    my $e = e40 EDGE_DATA_IPV6_BAD;
    $_[1] eq '-nodie' ? return $e : die $e;
}

sub validate_ip($;$) {
    if ($_[0] !~ m!^unix/!) {
        # Exclude "unix/" that can be TRUE from parse_address().
        my $ipn = AnyEvent::Socket::parse_address($_[0]);
        if (defined $ipn) {
            return 0;
        }
    }

    my $e = e40 EDGE_DATA_IP_BAD;
    $_[1] eq '-nodie' ? return $e : die $e;
}

sub validate_guid($;$) {
    if (!ref $_[0] && $_[0] =~ /^[a-f0-9]{4,128}$/i) {
        return 0;
    }

    my $e = e40 EDGE_DATA_GUID_BAD;
    $_[1] eq '-nodie' ? return $e : die $e;
}

sub _validate_domain($) {
    $_[0] = lc $_[0];
    ()
}

# Validation may change the domain representation
sub validate_domain($;$) {
    my ($domain, $arg) = @_;
    my $e;

    # Dirty domain check. TODO: use better validation including IDN in utf8
    # and punycode.
    $e ||= e40 EDGE_DATA_DOMAIN_EMPTY
        unless length $_[0];

    $e ||= e40 EDGE_DATA_DOMAIN_BAD
        unless !ref $_[0] && length $_[0] < 256;

    $e ||= e40 EDGE_DATA_DOMAIN_IDN
        if $_[0] =~ /[^\x00-\x7f]/;

    $e ||= e40 EDGE_DATA_DOMAIN_BAD
        unless $_[0] =~ /^[a-zA-Z0-9\.\-]+$/;

    $e ||= e40 EDGE_DATA_DOMAIN_NO_DOT
        unless $_[0] =~ /\./;

    unless ($e) {
        # Consider domain name valid.
        $_[0] = lc $_[0];
        return 0;
    }

    $_[1] eq '-nodie' ? return $e : die $e;
}

# Validation may change the CN server name representation
sub validate_cn_server_name {
    my ($domain, $arg) = @_;
    my $e;

    # Dirty domain check. TODO: use better validation including IDN in utf8
    # and punycode.
    $e ||= e40 EDGE_DATA_CN_SERVER_NAME_EMPTY
        unless length $_[0];

    $e ||= e40 EDGE_DATA_CN_SERVER_NAME_BAD
        unless !ref $_[0] && length $_[0] < 256;

    $e ||= e40 EDGE_DATA_CN_SERVER_NAME_IDN
        if $_[0] =~ /[^\x00-\x7f]/;

    $e ||= e40 EDGE_DATA_CN_SERVER_NAME_NO_DOT
        unless $_[0] =~ /\./;

    my $is_wildcard;
    my @split;

    unless ($e) {
        @split = split /\./, $_[0], -1;

        if ($split[0] eq '*') {
            shift @split;
            $is_wildcard = 1;

            $e = e40 EDGE_DATA_CN_SERVER_NAME_BAD_WCARD
                unless @split;
        }
    }

    unless ($e) {
        for my $name (@split) {
            unless ($name =~ /^[a-zA-Z0-9\-]+$/) {
                $e = e40 EDGE_DATA_CN_SERVER_NAME_BAD;
                last;
            }
        }
    }

    unless ($e) {
        # Consider domain name valid.
        $_[0] = lc $_[0];
        return 0;
    }

    $_[1] eq '-nodie' ? return $e : die $e;
}

sub validate_password($;$) {
    my ($pwd, $arg) = @_;
    my $e;

    $e ||= e40 EDGE_DATA_PWD_EMPTY
        unless length $_[0];

    $e ||= e40 EDGE_DATA_PWD_SHORT
        if length $_[0] < 6;

    unless ($e) {
        return 0;
    }

    $_[1] eq '-nodie' ? return $e : die $e;
}

sub validate_cert_name($;$) {
    my ($pwd, $arg) = @_;
    my $e;

    $e ||= e40 EDGE_DATA_CERT_NAME_EMPTY
        unless length $_[0];

    $e ||= e40 EDGE_DATA_CERT_NAME_BAD
        unless $_[0] =~ /\S/;

    unless ($e) {
        return 0;
    }

    $_[1] eq '-nodie' ? return $e : die $e;
}

# ------------------------------------------------------------------------------
# Public functions (data generators)
# ------------------------------------------------------------------------------
sub randstr24() {
    my @set = ('0' ..'9', 'a' .. 'z');
    my $str = join '' => map $set[int(rand scalar @set)], 1 .. 24;
    return $str;
}

1;
