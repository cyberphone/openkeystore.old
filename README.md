# openkeystore
Smart Card/TEE Key Store and Credential Provisioning System

This project defines SKS (Secure Key Store) which can hold X.509 certificates
and symmetric keys as well as associated attributes such as logotypes, key ACLs and URLs:<br>
https://cyberphone.github.io/openkeystore/resources/docs/sks-api-arch.pdf

The project also defines KeyGen2 which is a credential provisioning and management system
for SKS:<br>
https://cyberphone.github.io/openkeystore/resources/docs/keygen2.html

Currently only the "library" and "resources" projects are suitable for download:
```
$ cd library
$ ant
$ ant testsks
$ ant testkeygen2
```
There also is an Android proof-of-concept implementation:<br>
https://play.google.com/store/apps/details?id=org.webpki.mobile.android
