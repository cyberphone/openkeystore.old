REM Create a test root CA using our eminent Java CA stuff...

java org.webpki.ca.CommandLineCA -selfsigned -entity/ca -subject "CN=SKS Java Emulator Device Root CA, dc=webpki,dc=org" -validity/start 2009-07-10T10:00:00 -validity/end 2050-07-10T09:59:59 -out/keystore deviceca.jks -out/storepass testing -out/keypass testing -keysize 2048 -serial 1
keytool -export -v -keystore deviceca.jks -storepass testing -file deviceca.cer
keytool -list -v -keystore deviceca.jks -storepass testing
