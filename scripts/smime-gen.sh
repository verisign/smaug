#!/bin/sh

# # ##### BEGIN LICENSE BLOCK #####
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "MPL"); you may not use this file
# except in compliance with the MPL. You may obtain a copy of
# the MPL at http://www.mozilla.org/MPL/
#
# Software distributed under the MPL is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the MPL for the specific language governing
# rights and limitations under the MPL.
#
# The Original Code is Enigmail.
#
# The Initial Developer of the Original Code is Patrick Brunschwig.
# Portions created by Patrick Brunschwig <patrick@enigmail.net> are
# Copyright (C) 2005 Patrick Brunschwig. All Rights Reserved.
#
# Contributor(s):
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
# ##### END LICENSE BLOCK ##### #/


command openssl version -a
mkdir $HOME/sssmime
cat > $HOME/sssmime/config.cnf <<EOF

[ req ]
distinguished_name	= req_distinguished_name

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= US
countryName_min		= 2
countryName_max		= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Virginia
stateOrProvinceName_min	= 2
stateOrProvinceName_max	= 64

localityName			= Locality Name (eg, city)
localityName_default		= Reston
localityName_min		= 2
localityName_max		= 64

organizationName		= Organization Name (eg, company)
organizationName_default	= Verisign, Inc.
organizationName_min		= 2
organizationName_max		= 64

0.organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	= Operations
#organizationalUnitName_min	= 2
#organizationalUnitName_max	= 64

#1.organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	=
#organizationalUnitName_min	= 2
#organizationalUnitName_max	= 64

#2.organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	=
organizationalUnitName_min	= 2
organizationalUnitName_max	= 64

commonName			= Common Name (eg, YOUR name)
commonName_default		= John Smith
commonName_min			= 2
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64

[ v3smime ]
basicConstraints 		= CA:FALSE
keyUsage			= critical,digitalSignature,keyEncipherment
extendedKeyUsage		= clientAuth,emailProtection
subjectKeyIdentifier		= hash
#subjectAltName			= x500:20071211-1024smime
#authorityInfoAccess 		= caIssuers;URI:http://my.ca/ca.html
#authorityInfoAccess 		= OCSP;URI:http://ocsp.my.host/
nsCertType			= client, email

#ÇªÇÃëº
#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName
EOF

show_mainmenu()
{
    while true; do
    cat <<EOF
Key generation algorithm
    1: RSA 2048 bit - de facto standard
    2: RSA 4096 bit - strong de facto standard
    3: DSA 2048 bit - only if you know what you are doing
    4: DSA 4096 bit - only if you know what you are doing
    5: ECDSA 256 bit SECG curve - experimental
    6: ECDSA 384 bit NIST/SECG curve - experimental
    7: ECDSA 521 bit NIST/SECG curve - experimental
    8: Cancel
    Select desired key generation algorithm and key length.
EOF

    read key_algorithm
        case ${key_algorithm} in

            1)
            ntime=`eval date +%m%d%s`
            key_len=2048
            rsa_gen
            break
            ;;

            2)
            ntime=`eval date +%m%d%s`
            key_len=4096
            rsa_gen
            break
            ;;

            3)
            ntime=`eval date +%m%d%s`
            key_len=2048
            dsa_gen
            break
            ;;

            4)
            ntime=`eval date +%m%d%s`
            key_len=2048
            dsa_gen
            break
            ;;

            5)
            ntime=`eval date +%m%d%s`
            key_len="secp256k1"
            ecdsa_gen
            break
            ;;

            6)
            ntime=`eval date +%m%d%s`
            key_len="secp384r1"
            ecdsa_gen
            break
            ;;

            7)
            k_alg=ecdsa_gen
            ntime=`eval date +%m%d%s`
            key_len="secp521r1"
            ecdsa_gen
            break
            ;;

            8)
            break
            ;;

            *)
            printf "error: invalid input \"%s\" id input\n" "${ACT_MAIN}"
            ;;

        esac
    done
}

rsa_gen()
{
    k_nam=RSA
    command openssl genrsa -out $HOME/sssmime/"$k_nam""$key_len"_"$ntime".key "$key_len"
    echo Key generation done!
    command openssl req -config $HOME/sssmime/config.cnf -new -key $HOME/sssmime/"$k_nam""$key_len"_"$ntime".key -out $HOME/sssmime/"$k_nam""$key_len"_"$ntime".csr
    echo CSR generation done!
    sig_alg
}

dsa_gen()
{
    k_nam=DSA
    command openssl dsaparam -out $HOME/sssmime/dsapara.pem "$key_len"
    command openssl gendsa -out $HOME/sssmime/"$k_nam""$key_len"_"$ntime".key $HOME/sssmime/dsapara.pem
    echo Key generation done!
    command openssl req -config $HOME/sssmime/config.cnf -new -key $HOME/sssmime/"$k_nam""$key_len"_"$ntime".key -out $HOME/sssmime/"$k_nam""$key_len"_"$ntime".csr
    rm $HOME/sssmime/dsapara.pem
    echo CSR generation done!
    sig_alg
}

ecdsa_gen()
{
    k_nam=ECDSA
    command openssl ecparam -out $HOME/sssmime/"$k_nam""$key_len"_"$ntime".key -name "$key_len" -genkey
    echo Key generation done!
    openssl req -config $HOME/sssmime/config.cnf -new -key $HOME/sssmime/"$k_nam""$key_len"_"$ntime".key -out $HOME/sssmime/"$k_nam""$key_len"_"$ntime".csr
    echo CSR generation done!
    sig_alg
}

sig_alg()
{
    while true; do
    cat <<EOF
    Signing algorithm
    1: SHA1 - obsolete
    2: SHA256
    3: SHA384
    4: SHA512
    5: Cancel
    Select desired signing algorithm.
EOF

    read signalgo
        case ${signalgo} in

            1)
            algotype=-sha1
            ext_typ=v3smime
            set_day
            break
            ;;

            2)
            algotype=-sha256
            ext_typ=v3smime
            set_day
            break
            ;;

            3)
            algotype=-sha384
            ext_typ=v3smime
            set_day
            break
            ;;

            4)
            algotype=-sha512
            ext_typ=v3smime
            set_day
            break
            ;;

            5)
            break
            ;;

            *)
            printf "error: invalid input \"%s\" id input\n" "${ACT_MAIN}"
            ;;

        esac
    done
}

set_day()
{
    while true; do
    cat <<EOF
    Certificate validity
    1: 1 year (365 days)
    2: 2 year (730 days)
    3: 3 year (1095 days)
    4: 4 year (1460 days)
    5: 5 year (1825 days)
    6: Cancel
    Select desired validity period.
EOF

    read signday
        case ${signday} in

            1)
            val_day=365
            sig_csr
            break
            ;;

            2)
            val_day=730
            sig_csr
            break
            ;;

            3)
            val_day=1095
            sig_csr
            break
            ;;

            4)
            val_day=1460
            sig_csr
            break
            ;;

            5)
            val_day=1825
            sig_csr
            break
            ;;

            6)
            break
            ;;

            *)
            printf "error: invalid input \"%s\" id input\n" "${ACT_MAIN}"
            ;;

        esac
    done
}

sig_csr()
{
    command openssl x509 -req -in $HOME/sssmime/"$k_nam""$key_len"_"$ntime".csr -days "$val_day" -extfile $HOME/sssmime/config.cnf -extensions "$ext_typ" -set_serial "$ntime" -signkey $HOME/sssmime/"$k_nam""$key_len"_"$ntime".key "$algotype" -out $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".cer

    command openssl x509 -inform PEM -in $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".cer -outform DER -out $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der
    bundle_key
}

bundle_key()
{
    command openssl pkcs12 -export -out $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".p12 -in $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".cer -inkey $HOME/sssmime/"$k_nam""$key_len"_"$ntime".key
    command openssl pkcs12 -in $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".p12 -out $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime"-combined.pem -nodes
    # open $HOME/sssmime/
    # gen_smima
}

gen_smima()
{
    while true; do
    cat <<EOF
    DANE configuration
    1: Check SMIMEA RR against the entire certificate
    2: Check SMIMEA RR against the SHA256 hash of the entire certificate
    3: Check SMIMEA RR against the SHA512 hash of the entire certificate
    4: Check SMIMEA RR against the the publickeyInfo of the certificate
    5: Check SMIMEA RR against the SHA256 hash of the publickey of the certificate
    6: Check SMIMEA RR against the SHA512 hash of the publickey of the certificate
    7: Cancel

EOF

    read setattr
        case ${setattr} in

        1)
        cert_usage=3
        selector=0
        matching_type=0
        cadf=$(xxd -p $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der | tr -d '\n')
        #entire raw certificate
        gen_smimearr
        break
        ;;

        2)
        cert_usage=3
        selector=0
        matching_type=1
        cadf=$(openssl dgst -sha256 $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der | awk -F' ' '{print $2}')
        #SHA256 hash of the entire raw certificate
        gen_smimearr
        break
        ;;


        3)
        cert_usage=3
        selector=0
        matching_type=2
        cadf=$(openssl dgst -sha512 $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der | awk -F' ' '{print $2}')
        #SHA512 hash of the entire raw certificate
        gen_smimearr
        break
        ;;

        4)
        cert_usage=3
        selector=1
        matching_type=0
        cadf=$(openssl x509 -pubkey -inform DER -in $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der | openssl rsa -pubin | base64 -D | xxd -p | tr -d '\n')
        #raw publickeyinfo
        gen_smimearr
        break
        ;;

        5)
        cert_usage=3
        selector=1
        matching_type=1
        cadf=$(openssl x509 -pubkey -inform DER -in $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der | openssl rsa -pubin | base64 -D | openssl dgst -sha256)
        #SHA256 hash of the raw publickeyinfo
        gen_smimearr
        break
        ;;


        6)
        cert_usage=3
        selector=1
        matching_type=2
        cadf=$(openssl x509 -pubkey -inform DER -in $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der | openssl rsa -pubin | base64 -D | openssl dgst -sha512)
        #SHA512 hash of the raw publickeyinfo
        gen_smimearr
        break
        ;;

        7)
        break
        ;;

        *)
        printf "error: invalid input \"%s\" id input\n" "${ACT_MAIN}"
        ;;

        esac
    done
}

gen_smimearr()
{
    localadd=$(openssl x509 -email -inform DER -in $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der | sed -n '1p' | awk -F'@' '{print $1}' | openssl dgst -sha224)
    # domain=$(openssl x509 -email -inform DER -in $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der | sed -n '1p' | awk -F'@' '{print $2}')
    echo "$localadd""._smimecert.""$domain"" IN SMIMEA ( ""$cert_usage"" ""$selector"" ""$matching_type"" ""$cadf"" )" > $HOME/sssmime/"$k_nam""$key_len"SMIMEA_"$ntime".txt
#    rm $HOME/sssmime/"$k_nam""$key_len"_"$ntime".key $HOME/sssmime/"$k_nam""$key_len""$ext_typ"_"$ntime".der $HOME/sssmime/"$k_nam""$key_len"_"$ntime".csr

}
show_mainmenu
