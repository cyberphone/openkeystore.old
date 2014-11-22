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
package org.webpki.webapps.wcppsignaturedemo;

import java.io.IOException;
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

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyStoreReader;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;
import org.webpki.util.Base64URL;
import org.webpki.webutil.InitPropertyReader;

public class SignatureDemoService extends InitPropertyReader implements ServletContextListener
  {
    static Logger logger = Logger.getLogger (SignatureDemoService.class.getName ());
    
    static String issuer_url;
    static String relying_party_url;
    
    static String cross_data_uri;
    static String working_data_uri;
    static String mybank_data_uri;
    
    static String key_password;

    static KeyStore client_root_kestore;
    static String client_eecert_b64;
    static X509Certificate client_eecert;
    static String user_name;
    static JWK client_private_key;
    static String client_cert_data_js;

    static String certificate_filter_js;
    
    static byte[] pdf_sample;
    static String egov_log_uri;
    static String html_template_sample;
    
    static int reference_id = 1000000;
    
    public static String getDataURI (String mime_type, byte[] data) throws IOException
      {
        return "data:" + mime_type + ";base64," + new Base64 (false).getBase64StringFromBinary (data);
      }

    private byte[] getEmbeddedFile (String name) throws IOException
      {
        return ArrayUtil.getByteArrayFromInputStream (SignatureDemoService.class.getResourceAsStream (name));
      }

    private String getDataURI (String main, String extension) throws IOException
      {
        return getDataURI ("image/" + (extension.equals ("svg") ? "svg+xml" : extension),
                           getEmbeddedFile (main + "." + extension));
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

            issuer_url = getPropertyString ("issuer_url");
            relying_party_url = getPropertyString ("relying_party_url");

            cross_data_uri = getDataURI ("cross", "svg");
            egov_log_uri = getDataURI ("egovlogo", "svg");
            working_data_uri = getDataURI ("working", "gif");
            mybank_data_uri = getDataURI ("mybank", "svg");
            pdf_sample = getEmbeddedFile ("sampledoc.pdf");
            html_template_sample = new String (getEmbeddedFile ("sampledoc.html"), "UTF-8");

            key_password = getPropertyString ("key_password");
            X509Certificate client_root = 
                CertificateUtil.getCertificateFromBlob (
                    ArrayUtil.getByteArrayFromInputStream ( 
                       SignatureDemoService.class.getResourceAsStream (getPropertyString ("client_root"))));        
            client_root_kestore = KeyStore.getInstance ("JKS");
            client_root_kestore.load (null, null);
            client_root_kestore.setCertificateEntry ("mykey", client_root);        
            KeyStore client = KeyStoreReader.loadKeyStore (SignatureDemoService.class.getResourceAsStream (getPropertyString ("client_eecert")), SignatureDemoService.key_password);
            client_eecert = (X509Certificate) client.getCertificate ("mykey");
            user_name = new CertificateInfo (client_eecert).getSubjectCommonName ();
            client_eecert_b64 = Base64URL.encode (client_eecert.getEncoded ());
            client_cert_data_js = new StringBuffer ("{" + JSONSignatureDecoder.ISSUER_JSON + ":'")
              .append (client_eecert.getIssuerX500Principal ().getName ())
              .append ("', " + JSONSignatureDecoder.SERIAL_NUMBER_JSON + ":'")
              .append (client_eecert.getSerialNumber ().toString ())
              .append ("', " + JSONSignatureDecoder.SUBJECT_JSON + ":'")
              .append (client_eecert.getSubjectX500Principal ().getName ())
              .append ("'}").toString ();
            client_private_key = client_eecert.getPublicKey () instanceof RSAPublicKey ? 
                  new JWK (client.getKey ("mykey", SignatureDemoService.key_password.toCharArray ()))
                                    :
                  new JWK ((ECPublicKey)client_eecert.getPublicKey (), (ECPrivateKey)client.getKey ("mykey", SignatureDemoService.key_password.toCharArray ()));
            HTML.getHTMLSignatureFrameSource ();
            certificate_filter_js = new StringBuffer ("[{" + CertificateFilter.CF_ISSUER_REG_EX + ":'\\\\Q")
            .append (client_eecert.getIssuerX500Principal ().getName ())
            .append ("\\\\E', " + CertificateFilter.CF_FINGER_PRINT + ":'")
            .append (Base64URL.encode (HashAlgorithms.SHA256.digest (client_root.getEncoded ())))
            .append ("', " + CertificateFilter.CF_KEY_USAGE_RULES + ":['")
            .append (KeyUsageBits.NON_REPUDIATION.getX509Name ())
            .append ("']}]").toString ();
            logger.info ("WebCrypto++ Signature Demo ClientKey=" + client_private_key.getKeyType () + " Successfully Initiated");
          }
        catch (Exception e)
          {
            logger.log(Level.SEVERE, "********\n" + e.getMessage() + "\n********", e);
          }
      }
  }
