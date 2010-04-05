REM Create a test root CA using our eminent Java CA stuff...

java org.webpki.ca.CommandLineCA -selfsigned -entity/ca -subject "CN=Test SSL CA, O=The Lab" -validity/start 2002-07-10T10:00:00 -validity/end 2020-07-10T09:59:59 -out/keystore sslrootca.ks -out/storepass testing -out/keypass theroot -keysize 2048 -serial 1
keytool -export -v -keystore sslrootca.ks -storepass testing -file sslrootca.cer
keytool -list -v -keystore sslrootca.ks -storepass testing
