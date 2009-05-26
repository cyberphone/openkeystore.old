REM Create a test root CA using our eminent Java CA stuff...

java org.webpki.ca.CommandLineCA -selfsigned -entity/ca -subject "CN=MyBank Root CA, O=MyBank Consumer Banking, c=us" -validity/start 2002-07-10T10:00:00 -validity/end 2022-07-10T09:59:59 -out/keystore mybankca.ks -out/storepass testing -out/keypass theroot -keysize 2048 -serial 1
keytool -export -v -keystore mybankca.ks -storepass testing -file mybankca.cer
keytool -list -v -keystore mybankca.ks -storepass testing
java org.webpki.ca.CommandLineCA -ca/keystore mybankca.ks -ca/storepass testing -ca/keypass theroot -entity/ca -subject "CN=MyBank Sub CA 1, O=MyBank Consumer Banking, c=us" -validity/start 2002-07-10T10:00:00 -validity/end 2022-07-10T09:59:59 -out/keystore mybankca.ks -out/storepass testing -out/keypass theca -keysize 2048 -serial 2 -ca/addpath all
keytool -export -v -keystore mybankca.ks -storepass testing -file mybanksubca1.cer
keytool -list -v -keystore mybankca.ks -storepass testing

