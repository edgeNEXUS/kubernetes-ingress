package Edge::ClientAPI::Util::Cert;
use common::sense;
use Carp;
use Data::Dumper;
use Net::SSLeay;
use Crypt::OpenSSL::PKCS12;
use IO::Socket::SSL::Utils; # for PEM_string2cert
use Try::Tiny;
use File::Temp;
use Edge::ClientAPI::E
    CERT_INFO_PKCS12_STRING_EMPTY   => [ 9400, "PKCS12 certificate empty" ],
    CERT_INFO_PKCS12_FILE_NOT_SET   => [ 9401, "PKCS12 file is not set" ],
    CERT_INFO_PKCS12_FILE_NOT_FOUND => [ 9402, "PKCS12 file doesn't exists" ],
    CERT_INFO_PKCS12_FILE_EMPTY     => [ 9403, "PKCS12 certificate empty" ],
    CERT_INFO_PKCS12_PASSWORD_BAD   => [ 9404, "Invalid password for PFX" ],
    CERT_INFO_BAD_DATES             => [ 9405, "Couldn't obtain certificate dates" ],
    CERT_INFO_BAD_DOMAIN            => [ 9406, "Couldn't obtain certificate domain name" ],
    CERT_INFO_PKCS12_ERROR          => [ 9407, "PKCS12: %s" ],
;

sub new {
    my ($class, %args) = @_;
    my $self = +{};
    my $is_file;

    my $tmp;
    if (exists $args{pkcs12_string}) {
        die e40 CERT_INFO_PKCS12_STRING_EMPTY
            unless length $args{pkcs12_string};

        # Crypt::OpenSSL::PKCS12->new_from_string is buggy, as they use strlen()
        # to determine PKCS12 buffer length, but PKCS12 may contain \x00 chars
        $tmp = File::Temp->new(UNLINK => 1, SUFFIX => '.dat');
        binmode $tmp;
        print $tmp $args{pkcs12_string};
        $tmp->flush;
        $args{pkcs12_file} = "$tmp";
    }

    if (exists $args{pkcs12_file}) {
        die e40 CERT_INFO_PKCS12_FILE_NOT_SET
            unless length $args{pkcs12_file};

        die e40 CERT_INFO_PKCS12_FILE_NOT_FOUND
            if !-e $args{pkcs12_file} || -d $args{pkcs12_file};

        die e40 CERT_INFO_PKCS12_FILE_EMPTY
            unless -s $args{pkcs12_file};

        $is_file = 1;
    }
    else {
        croak "Invalid arguments to build object of ", __PACKAGE__;
    }

    try {
        $self->{pkcs12} = $is_file
                        ? Crypt::OpenSSL::PKCS12
                                ->new_from_file($args{pkcs12_file})
                        : Crypt::OpenSSL::PKCS12
                                ->new_from_string($args{pkcs12_string});
        undef $tmp;
    } catch {
        my $err = $_;
        $err =~ s/^\s*\:?\s*//;
        $err =~ s/^.....\s+//;
        die e40_format CERT_INFO_PKCS12_ERROR, $err;
    };

    $self->{pkcs12_password} = $args{pkcs12_password};
    bless $self, $class;

    my $cert_pem = $self->pkcs12->certificate($args{pkcs12_password} // '');

    unless ($cert_pem =~ /^-----BEGIN CERTIFICATE-----/) {
        die e40 CERT_INFO_PKCS12_PASSWORD_BAD;
    }

    $self->_get_info($cert_pem);

    return $self;
}

sub pkcs12          { $_[0]{pkcs12}   }
sub pkcs12_password { $_[0]{pkcs12_password} }
sub info            { $_[0]{info}     }
sub info_cert_pem   { $_[0]{info}{cert_pem} }

sub _get_info {
    my ($self, $cert_pem) = @_;
    my $cert = PEM_string2cert($cert_pem);

    my %info;

    $info{fingerprint} = Net::SSLeay::X509_get_fingerprint($cert, 'SHA-1');

    my $valid_to    = Net::SSLeay::P_ASN1_TIME_get_isotime(
                        Net::SSLeay::X509_get_notAfter($cert));

    my $valid_from  = Net::SSLeay::P_ASN1_TIME_get_isotime(
                        Net::SSLeay::X509_get_notBefore($cert));

    $valid_from =~ s/T.+$//;
    $valid_to   =~ s/T.+$//;

    unless (length $valid_from && length $valid_to) {
        CERT_free($cert);
        die e40 CERT_INFO_BAD_DATES;
    }

    ($info{valid_to}, $info{valid_from}) = ($valid_to, $valid_from);

    # e.g. /C=US/ST=California/O=ElectricRain/CN=test.electricrain.com
    my $subject_name = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($cert));

    unless ($subject_name =~ m!/CN=([^/]+)!) {
        CERT_free($cert);
        die e40 CERT_INFO_BAD_DOMAIN;
    }

    $info{issued_to}    = $1; # e.g. test.electricrain.com
    $info{subject_name} = $subject_name;

    # e.g. /C=US/O=(STAGING) Let's Encrypt/CN=(STAGING) Artificial Apricot R3
    $info{issuer_name}  = Net::SSLeay::X509_NAME_oneline(
                                Net::SSLeay::X509_get_issuer_name($cert));

    $info{issued_by} = $info{issuer_name};
    $info{issued_by} =~ s!/[^=]+=! !g;
    $info{issued_by} =~ s!^\s+!!;
    $info{issued_by} =~ s!\s+$!!;

    $info{cert_pem}  = $cert_pem;

    CERT_free($cert);

    $self->{info} = \%info;
    ()
}

sub TO_JSON { undef }

1;
