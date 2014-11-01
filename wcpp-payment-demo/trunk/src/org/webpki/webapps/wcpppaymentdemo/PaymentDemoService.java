/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.webapps.wcpppaymentdemo;

import java.io.IOException;

import java.net.URL;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

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

public class PaymentDemoService extends InitPropertyReader implements ServletContextListener
  {
    static Logger logger = Logger.getLogger (PaymentDemoService.class.getName ());
    
    static String bank_url;
    static String payment_url;
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
    static JWK bank_encryption_key;
    
    static KeyStore client_root;
    static String client_eecert;
    static JWK client_private_key;
    static String cert_data;

    private String getDataURI (String main, String extension) throws IOException
      {
        byte[] image = ArrayUtil.getByteArrayFromInputStream (PaymentDemoService.class.getResourceAsStream (main + "." + extension));
        return "data:image/" + extension + ";base64," + new Base64 (false).getBase64StringFromBinary (image);
      }
    
    private KeyStore getRootCertificate (String resource_name) throws IOException, GeneralSecurityException
      {
        KeyStore ks = KeyStore.getInstance ("JKS");
        ks.load (null, null);
        ks.setCertificateEntry ("mykey",
                                CertificateUtil.getCertificateFromBlob (
                                    ArrayUtil.getByteArrayFromInputStream ( 
                                        PaymentDemoService.class.getResourceAsStream (resource_name))));        
        return ks;
      }

    @Override
    public void contextDestroyed (ServletContextEvent event)
      {
      }

    @Override
    public void contextInitialized (ServletContextEvent event)
      {
        initProperties (event);
        try 
          {
            CustomCryptoProvider.forcedLoad (getPropertyBoolean ("bouncycastle_first"));
            bank_url = getPropertyString ("bank_url");
            merchant_url = getPropertyString ("merchant_url");
            if (getPropertyString ("bank_port_map").length () > 0)
              {
                URL url = new URL (bank_url);
                payment_url = new URL (url.getProtocol (),
                                       url.getHost (),
                                       getPropertyInt ("bank_port_map"),
                                       url.getFile ()).toExternalForm ();
              }
            else
              {
                payment_url = bank_url;
              }
            web_crypto = getPropertyBoolean ("web_crypto");
            cross_data_uri = getDataURI ("cross", "png");
            working_data_uri = getDataURI ("working", "gif");
            card_font = getPropertyString ("card_font");
            key_password = getPropertyString ("key_password");
            bank_eecert_key = KeyStoreReader.loadKeyStore (PaymentDemoService.class.getResourceAsStream (getPropertyString ("bank_eecert")), PaymentDemoService.key_password);
            merchant_eecert_key = KeyStoreReader.loadKeyStore (PaymentDemoService.class.getResourceAsStream (getPropertyString ("merchant_eecert")), PaymentDemoService.key_password);
            payment_root = getRootCertificate (getPropertyString ("payment_root"));
            merchant_root = getRootCertificate (getPropertyString ("merchant_root"));
            bank_encryption_key = new JWK (CertificateUtil.getCertificateFromBlob (
                                      ArrayUtil.getByteArrayFromInputStream ( 
                                          PaymentDemoService.class.getResourceAsStream (
                                              getPropertyString ("bank_encryptionkey")))).getPublicKey ());
            bank_decryption_key = KeyStoreReader.loadKeyStore (PaymentDemoService.class.getResourceAsStream (getPropertyString ("bank_decryptionkey")), PaymentDemoService.key_password);
            client_root = getRootCertificate (getPropertyString ("bank_client_root"));
            KeyStore client = KeyStoreReader.loadKeyStore (PaymentDemoService.class.getResourceAsStream (getPropertyString ("bank_client_eecert")), PaymentDemoService.key_password);
            X509Certificate cert = (X509Certificate) client.getCertificate ("mykey");
            client_eecert = Base64URL.encode (cert.getEncoded ());
            cert_data = new StringBuffer ("{" + JSONSignatureDecoder.ISSUER_JSON + ":'")
              .append (cert.getIssuerX500Principal ().getName ())
              .append ("', " + JSONSignatureDecoder.SERIAL_NUMBER_JSON + ":'")
              .append (cert.getSerialNumber ().toString ())
              .append ("', " + JSONSignatureDecoder.SUBJECT_JSON + ":'")
              .append (cert.getSubjectX500Principal ().getName ())
              .append ("'}").toString ();
            client_private_key = cert.getPublicKey () instanceof RSAPublicKey ? 
                  new JWK (client.getKey ("mykey", PaymentDemoService.key_password.toCharArray ()))
                                    :
                  new JWK ((ECPublicKey)cert.getPublicKey (), (ECPrivateKey)client.getKey ("mykey", PaymentDemoService.key_password.toCharArray ()));
            logger.info ("WebCrypto++ Payment Demo - " + (web_crypto ? "WebCrypto ClientKey=" + client_private_key.getKeyType () + " BankKey=" +  bank_encryption_key.getKeyType () : "Standard Mode") + " Successfully Initiated");
          }
        catch (Exception e)
          {
            logger.log(Level.SEVERE, "********\n" + e.getMessage() + "\n********", e);
          }
      }
  }
