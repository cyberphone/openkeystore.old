package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyStoreReader;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;
import org.webpki.util.Base64URL;
import org.webpki.webutil.InitPropertyReader;

public class Init implements ServletContextListener
  {
    static Logger logger = Logger.getLogger (Init.class.getName ());
    
    static
      {
        CustomCryptoProvider.forcedLoad ();
      }
  
    static String bank_url;
    static String merchant_url;
    static boolean web_crypto;
    
    static String cross_data_uri;
    static String working_data_uri;
    
    static String card_font;

    static String key_password;

    static KeyStore bank_eecert_key;
    static KeyStore merchant_eecert_key;
    
    static KeyStore merchant_root;
    static KeyStore payment_root;
    
    static KeyStore bank_decryption_key;
    static byte[] bank_encryption_key;
    
    static KeyStore client_root;
    static String client_eecert;
    static byte[] client_key;
    static String cert_data;

    private String getDataURI (String main, String extension) throws IOException
      {
        byte[] image = ArrayUtil.getByteArrayFromInputStream (Init.class.getResourceAsStream (main + "." + extension));
        return "data:image/" + extension + ";base64," + new Base64 (false).getBase64StringFromBinary (image);
      }
    
    private KeyStore getRootCertificate (String resource_name) throws IOException, GeneralSecurityException
      {
        KeyStore ks = KeyStore.getInstance ("JKS");
        ks.load (null, null);
        ks.setCertificateEntry ("mykey",
                                CertificateUtil.getCertificateFromBlob (
                                    ArrayUtil.getByteArrayFromInputStream ( 
                                        Init.class.getResourceAsStream (resource_name))));        
        return ks;
      }

    @Override
    public void contextDestroyed (ServletContextEvent event)
      {
      }

    @Override
    public void contextInitialized (ServletContextEvent event)
      {
        InitPropertyReader properties = new InitPropertyReader ();
        properties.initProperties (event);
        try 
          {
            bank_url = properties.getPropertyString ("bank_url");
            merchant_url = properties.getPropertyString ("merchant_url");
            web_crypto = properties.getPropertyBoolean ("web_crypto");
            cross_data_uri = getDataURI ("cross", "png");
            working_data_uri = getDataURI ("working", "gif");
            card_font = properties.getPropertyString ("card_font");
            key_password = properties.getPropertyString ("key_password");
            bank_eecert_key = KeyStoreReader.loadKeyStore (Init.class.getResourceAsStream (properties.getPropertyString ("bank_eecert")), Init.key_password);
            merchant_eecert_key = KeyStoreReader.loadKeyStore (Init.class.getResourceAsStream (properties.getPropertyString ("merchant_eecert")), Init.key_password);
            payment_root = getRootCertificate (properties.getPropertyString ("payment_root"));
            merchant_root = getRootCertificate (properties.getPropertyString ("merchant_root"));
            bank_encryption_key = CertificateUtil.getCertificateFromBlob (
                                      ArrayUtil.getByteArrayFromInputStream ( 
                                          Init.class.getResourceAsStream (
                                              properties.getPropertyString ("bank_encryptionkey")))).getPublicKey ().getEncoded ();
            bank_decryption_key = KeyStoreReader.loadKeyStore (Init.class.getResourceAsStream (properties.getPropertyString ("bank_decryptionkey")), Init.key_password);
            client_root = getRootCertificate (properties.getPropertyString ("bank_client_root"));
            KeyStore client = KeyStoreReader.loadKeyStore (Init.class.getResourceAsStream (properties.getPropertyString ("bank_client_eecert")), Init.key_password);
            X509Certificate cert = (X509Certificate) client.getCertificate ("mykey");
            client_eecert = Base64URL.encode (cert.getEncoded ());
            cert_data = new StringBuffer ("{" + JSONSignatureDecoder.ISSUER_JSON + ":'")
              .append (cert.getIssuerX500Principal ().getName ())
              .append ("', " + JSONSignatureDecoder.SERIAL_NUMBER_JSON + ":'")
              .append (cert.getSerialNumber ().toString ())
              .append ("', " + JSONSignatureDecoder.SUBJECT_JSON + ":'")
              .append (cert.getSubjectX500Principal ().getName ())
              .append ("'}").toString ();
            client_key = client.getKey ("mykey", Init.key_password.toCharArray ()).getEncoded ();
            logger.info ("WebCrypto++ Payment Demo - " + (web_crypto ? "WebCrypto ": "Standard") + " Mode Successfully Initiated");
          }
        catch (Exception e)
          {
            logger.log(Level.SEVERE, "********\n" + e.getMessage() + "\n********", e);
          }
      }
  }
