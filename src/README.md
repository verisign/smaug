Usable/Useful Test and Utilities:

## Compiling and Running

make clean
make all

## To generate dane_email_test, domain_client_test, and hash_test
make test


To test/verify generation of a sha224 hash on a string:
   hash_test <string>

To test the existance of an _encr or _sign key record:
   dane_email_test <email address>

To test a hard coded client-server decryption:
   ## This depends on  existing files and public/private key access
   ## existing.  MAY BE BROKEN AT ANY POINT due to dependencies
   ./domain_socket_srv & ./domain_client_test





ETC:
http://stackoverflow.com/questions/24449980/handling-blank-lines-in-email-headers
