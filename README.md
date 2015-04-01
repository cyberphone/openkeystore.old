# openkeystore
Smart Card/TEE Key Store and Credential Provisioning System

This project defines SKS (Secure Key Store) which can hold X.509 certificates
and symmetric keys as well as associated attributes such as logotypes, key ACLs and URLs:<br>
https://cyberphone.github.io/openkeystore/resources/docs/sks-api-arch.pdf

The project also defines KeyGen2 which is a credential provisioning and management system
for SKS:<br>
https://cyberphone.github.io/openkeystore/resources/docs/keygen2.html

##Requirements
* Java SDK Version 6, 7 or 8
* Ant 1.8 or later
* The projects are being developed using Eclipse but there's no dependence on Eclipse.

Currently only the "library" and "resources" projects are suitable for download:
```
$ cd library
$ ant
$ ant testsks
$ ant testkeygen2
```
##Proof of Concept Implementation
There also is an Android proof-of-concept implementation which allows you to test provisioning
and then using provisioned keys for authentication:<br>
https://play.google.com/store/apps/details?id=org.webpki.mobile.android
