REM Create an ee cert using our eminent Java CA stuff...
REM just give the host as argument!

java -cp ../../library/dist/webpki.org-libext-1.00.jar;../third-party-jars/bcprov-jdk16-142.jar org.webpki.ca.CommandLineCA -ca/keystore sslrootca.jks -ca/storepass testing -ca/keypass theroot -entity/ee -subject "CN=%1, o=The Lab" -validity/start 2005-03-10T10:00:00 -validity/end 2015-03-10T09:59:59 -out/keystore %1.jks -out/storepass testing -out/keypass testing
keytool -list -v -keystore %1.jks -storepass testing
keytool -export -v -keystore %1.jks -storepass testing -file %1.cer

