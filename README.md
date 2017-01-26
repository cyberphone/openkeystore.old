# openkeystore
Smart Card/TEE Key Store and Credential Provisioning System

This project defines SKS (Secure Key Store) which can hold X.509 certificates
and symmetric keys as well as associated attributes such as logotypes, key ACLs and URLs:<br>
https://cyberphone.github.io/doc/security/sks-api-arch.pdf

The project also defines KeyGen2 which is a credential provisioning and management system
for SKS:<br>
https://cyberphone.github.io/doc/security/keygen2.html

The JSON library supports a clear text signature system called JCS:<br>
https://cyberphone.github.io/doc/security/jcs.html<br>
as well as a "matching" encryption scheme coined JEF:<br>
https://cyberphone.github.io/doc/security/jef.html

##Requirements
* Java SDK Version 6, 7 or 8
* Ant 1.8 or later
* The projects are being developed using Eclipse but there's no dependence on Eclipse.

Currently only the "library" and "resources" projects are suitable public use.
To create the openkeystore library, perform the following steps:
```
$ cd library
$ ant
$ ant testsks
$ ant testkeygen2
$ ant testjson
```
Now you should have a file <code>library/dist/webpki.org-libext-1.00.jar</code> which
implements the API described on https://cyberphone.github.io/doc/openkeystore/javaapi/overview-summary.html.
##Proof of Concept Implementation
There also is an Android proof-of-concept implementation which allows you to test provisioning
and then using provisioned keys for authentication:<br>
https://play.google.com/store/apps/details?id=org.webpki.mobile.android
