REM Create a test root CA using our eminent Java CA stuff...

java org.webpki.ca.CommandLineCA -selfsigned -entity/ca -subject "CN=Mobile Device Root CA, dc=webpki,dc=org" -validity/start 2002-07-10T10:00:00 -validity/end 2050-07-10T09:59:59 -out/keystore deviceca.ks -out/storepass testing -out/keypass theroot -keysize 2048 -serial 1
keytool -export -v -keystore deviceca.ks -storepass testing -file deviceca.cer
keytool -list -v -keystore deviceca.ks -storepass testing
