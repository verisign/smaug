## Use this once for the CA
openssl genrsa -des3 -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

## in each directory for users, do the following:
## with passphrase
## openssl genrsa -des3 -out smime.key 4096
## without  passphrase
openssl genrsa -out smime.key 4096


##################################################################################################
##### <begin> create working keyset 
##################################################################################################

openssl req -new -key smime.key -out smime.csr
openssl x509 -req -days 365 -in smime.csr -CA ca.crt -CAkey ca.key -set_serial 1 -out smime.crt -setalias "Self Signed SMIME" -addtrust emailProtection -addreject clientAuth -addreject serverAuth -trustout


## create private key in format and remove passphrase
openssl rsa -in smime.key -out smime.nocrypt.key

## This is for Linux, on the mac, push to ~/Library/Thunderbird/certs
cp smime.nocrypt.key ~/.thunderbird/certs/cert.pem 
 

openssl pkcs12 -export -in smime.crt -inkey smime.key -out smime.p12
openssl pkcs12 -in smime.p12 -clcerts -nokeys -out publicCert.pem

cat publicCert.pem|xxd -c 256 -ps > _encr.key.pub
cat publicCert.pem|xxd -c 256 -ps > _sign.key.pub

## now push [_sign|_encr].cert.txt into SMIMEA record prepending '2 0 0'

## push signing file into place
## This is for Linux, on the mac, push to ~/Library/Thunderbird/certs
cat publicCert.pem smime.key > ~/.thunderbird/certs/smime.pem 

##################################################################################################
##### <end> create working keyset 
##################################################################################################



################################
####  Validation of signing ####
openssl smime -sign -in message.txt -out message.signed -signer smime.crt -inkey smime.key
../../src/test_vrfy <message.signed> <sender email>
################################

