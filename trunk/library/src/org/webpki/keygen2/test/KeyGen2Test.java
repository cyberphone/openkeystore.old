/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2.test;

import java.io.FileOutputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.AfterClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.rules.TestName;

import static org.junit.Assert.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.ca.CA;
import org.webpki.ca.CertSpec;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ECDomains;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.keygen2.Action;
import org.webpki.keygen2.KeySpecifier;
import org.webpki.keygen2.ProvisioningFinalizationRequestDecoder;
import org.webpki.keygen2.ProvisioningFinalizationRequestEncoder;
import org.webpki.keygen2.ProvisioningFinalizationResponseDecoder;
import org.webpki.keygen2.ProvisioningFinalizationResponseEncoder;
import org.webpki.keygen2.CredentialDiscoveryRequestDecoder;
import org.webpki.keygen2.CredentialDiscoveryRequestEncoder;
import org.webpki.keygen2.CredentialDiscoveryResponseDecoder;
import org.webpki.keygen2.CredentialDiscoveryResponseEncoder;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyCreationResponseDecoder;
import org.webpki.keygen2.KeyCreationResponseEncoder;
import org.webpki.keygen2.KeyCreationRequestDecoder;
import org.webpki.keygen2.KeyCreationRequestEncoder;
import org.webpki.keygen2.PlatformNegotiationRequestDecoder;
import org.webpki.keygen2.PlatformNegotiationRequestEncoder;
import org.webpki.keygen2.PlatformNegotiationResponseDecoder;
import org.webpki.keygen2.PlatformNegotiationResponseEncoder;
import org.webpki.keygen2.ProvisioningInitializationRequestDecoder;
import org.webpki.keygen2.ProvisioningInitializationRequestEncoder;
import org.webpki.keygen2.ProvisioningInitializationResponseDecoder;
import org.webpki.keygen2.ProvisioningInitializationResponseEncoder;
import org.webpki.keygen2.ServerCredentialStore;
import org.webpki.keygen2.ServerCryptoInterface;

import org.webpki.sks.AppUsage;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.InputMethod;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyData;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.Property;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.tools.XML2HTMLPrinter;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HTMLHeader;

import org.webpki.xml.XMLSchemaCache;
import org.webpki.xml.XMLObjectWrapper;

/*
 * KeyGen2 "Protocol Exerciser" / JUnit Test
 */
public class KeyGen2Test
  {
    static final byte[] TEST_STRING = {'S','u','c','c','e','s','s',' ','o','r',' ','n','o','t','?'};

    boolean pin_protection;
    
    boolean private_key_backup;
    
    boolean ecc_key;
    
    boolean key_agreement;
    
    boolean server_seed;
    
    boolean property_bag;
    
    boolean symmetric_key;
    
    boolean updatable;
    
    boolean ecc_kmk;
    
    Server clone_key_protection;
    
    Server update_key;
    
    Server delete_key;
    
    Server plain_unlock_key;
    
    boolean device_pin_protection;
    
    boolean pin_group_shared;
    
    boolean puk_protection;
    
    boolean add_pin_pattern;
    
    boolean preset_pin;
    
    boolean encryption_key;
    
    boolean set_private_key;
    
    boolean encrypted_extension;
    
    boolean https;  // Use server-cert
    
    boolean ask_for_4096;
    
    ExportProtection export_protection;
    
    DeleteProtection delete_protection;
    
    InputMethod input_method;
    
    boolean image_prefs;
    
    static FileOutputStream fos;
    
    static SecureKeyStore sks;
    
    static boolean html_mode;

    static final byte[] OTP_SEED = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    
    static final byte[] AES32BITKEY = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    
    static final byte[] USER_DEFINED_PIN = {'0','1','5','3','5','4'};

    static X509Certificate server_certificate;

    int round;
   
    @BeforeClass
    public static void openFile () throws Exception
      {
        html_mode = new Boolean (System.getProperty ("html.mode", "false"));
        String dir = System.getProperty ("test.dir");
        if (dir.length () > 0)
          {
            fos = new FileOutputStream (dir + "/" + KeyGen2Test.class.getCanonicalName () + (html_mode ? ".html" : ".txt"));
            if (html_mode)
              {
                fos.write (HTMLHeader.createHTMLHeader (false, true,"KeyGen2 JUinit test output", null).append ("<body><h3>KeyGen2 JUnit Test</h3><p>").toString ().getBytes ("UTF-8"));
              }
          }
        Security.insertProviderAt (new BouncyCastleProvider(), 1);
        sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.implementation")).newInstance ();
        server_certificate = (X509Certificate) CertificateFactory.getInstance ("X.509").generateCertificate (KeyGen2Test.class.getResourceAsStream ("server-certificate.der"));
      }

    @AfterClass
    public static void closeFile () throws Exception
      {
        if (fos != null)
          {
            if (html_mode)
              {
                fos.write ("</body></html>".getBytes ("UTF-8"));
              }
            fos.close ();
          }
      }
    
    @Rule 
    public TestName _name = new TestName();

    class Client
      {
        XMLSchemaCache client_xml_cache;
        
        int provisioning_handle;
        
        KeyCreationRequestDecoder key_init_request;
        
        ProvisioningInitializationRequestDecoder prov_sess_req;
        
        CredentialDiscoveryRequestDecoder cre_disc_req;
        
        DeviceInfo device_info;
        
        Client () throws IOException
          {
            client_xml_cache = new XMLSchemaCache ();
            client_xml_cache.addWrapper (PlatformNegotiationRequestDecoder.class);
            client_xml_cache.addWrapper (ProvisioningInitializationRequestDecoder.class);
            client_xml_cache.addWrapper (CredentialDiscoveryRequestDecoder.class);
            client_xml_cache.addWrapper (KeyCreationRequestDecoder.class);
            client_xml_cache.addWrapper (ProvisioningFinalizationRequestDecoder.class);
          }

        private void abort (String message) throws IOException, SKSException
          {
            sks.abortProvisioningSession (provisioning_handle);
            throw new IOException (message);
          }
        
        private void postProvisioning (ProvisioningFinalizationRequestDecoder.PostOperation post_operation, int handle) throws IOException, GeneralSecurityException
          {
            EnumeratedProvisioningSession old_provisioning_session = new EnumeratedProvisioningSession ();
            while (true)
              {
                if ((old_provisioning_session = sks.enumerateProvisioningSessions (old_provisioning_session.getProvisioningHandle (), false)) == null)
                  {
                    abort ("Old provisioning session not found:" + 
                        post_operation.getClientSessionID () + "/" +
                        post_operation.getServerSessionID ());
                  }
                if (old_provisioning_session.getClientSessionID ().equals(post_operation.getClientSessionID ()) &&
                    old_provisioning_session.getServerSessionID ().equals (post_operation.getServerSessionID ()))
                  {
                    break;
                  }
              }
            EnumeratedKey ek = new EnumeratedKey ();
            while (true)
              {
                if ((ek = sks.enumerateKeys (ek.getKeyHandle ())) == null)
                  {
                    abort ("Old key not found");
                  }
                if (ek.getProvisioningHandle () == old_provisioning_session.getProvisioningHandle ())
                  {
                    KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                    if (ArrayUtil.compare (HashAlgorithms.SHA256.digest (ka.getCertificatePath ()[0].getEncoded ()), post_operation.getCertificateFingerprint ()))
                      {
                        switch (post_operation.getPostOperation ())
                          {
                            case ProvisioningFinalizationRequestDecoder.PostOperation.CLONE_KEY_PROTECTION:
                              sks.pp_cloneKeyProtection (handle, ek.getKeyHandle (), post_operation.getAuthorization (), post_operation.getMAC ());
                              break;

                            case ProvisioningFinalizationRequestDecoder.PostOperation.UPDATE_KEY:
                              sks.pp_updateKey (handle, ek.getKeyHandle (),  post_operation.getAuthorization (), post_operation.getMAC ());
                              break;

                            case ProvisioningFinalizationRequestDecoder.PostOperation.UNLOCK_KEY:
                              sks.pp_unlockKey (handle, ek.getKeyHandle (),  post_operation.getAuthorization (), post_operation.getMAC ());
                              break;

                            default:
                              sks.pp_deleteKey (handle, ek.getKeyHandle (), post_operation.getAuthorization (), post_operation.getMAC ());
                          }
                        return;
                      }
                  }
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get platform request and respond with SKS compatible data
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] platformResponse (byte[] xmldata) throws IOException
          {
            PlatformNegotiationRequestDecoder platform_req = (PlatformNegotiationRequestDecoder) client_xml_cache.parse (xmldata);
            device_info = sks.getDeviceInfo ();
            PlatformNegotiationResponseEncoder platform_response = 
              new PlatformNegotiationResponseEncoder (platform_req);
            Vector<Short> matches = new Vector<Short> ();
            for (short key_size : platform_req.getBasicCapabilities ().getRSAKeySizes ())
              {
                for (short d_key_size : device_info.getRSAKeySizes ())
                  {
                    if (key_size == d_key_size)
                      {
                        matches.add (key_size);
                        break;
                      }
                  }
              }
            if (!matches.isEmpty () && matches.size () != device_info.getRSAKeySizes ().length)
              {
                for (short key_size : matches)
                  {
                    platform_response.getBasicCapabilities ().addRSAKeySize (key_size);
                  }
              }
            if (image_prefs)
              {
                platform_response.addImagePreference (KeyGen2URIs.LOGOTYPES.CARD, "image/png", 200, 120);
              }
            return platform_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session request and respond with ephemeral keys and and attest
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] provSessResponse (byte[] xmldata) throws IOException
          {
            prov_sess_req = (ProvisioningInitializationRequestDecoder) client_xml_cache.parse (xmldata);
            Date client_time = new Date ();
            ProvisioningSession sess = 
                  sks.createProvisioningSession (prov_sess_req.getSessionKeyAlgorithm (),
                                                 prov_sess_req.getServerSessionID (),
                                                 prov_sess_req.getServerEphemeralKey (),
                                                 prov_sess_req.getSubmitURL (), /* IssuerURI */
                                                 prov_sess_req.getKeyManagementKey (),
                                                 (int)(client_time.getTime () / 1000),
                                                 prov_sess_req.getSessionLifeTime (),
                                                 prov_sess_req.getSessionKeyLimit ());
            provisioning_handle = sess.getProvisioningHandle ();
            
            ProvisioningInitializationResponseEncoder prov_sess_response = 
                  new ProvisioningInitializationResponseEncoder (sess.getClientEphemeralKey (),
                                                                 prov_sess_req.getServerSessionID (),
                                                                 sess.getClientSessionID (),
                                                                 prov_sess_req.getServerTime (),
                                                                 client_time,
                                                                 sess.getAttestation (),
                                                                 device_info.getCertificatePath ());
            if (https)
              {
                prov_sess_response.setServerCertificate (server_certificate);
              }
            prov_sess_response.signRequest (new SymKeySignerInterface ()
              {
                public MacAlgorithms getMacAlgorithm () throws IOException, GeneralSecurityException
                  {
                    return MacAlgorithms.HMAC_SHA256;
                  }

                public byte[] signData (byte[] data) throws IOException, GeneralSecurityException
                  {
                    return sks.signProvisioningSessionData (provisioning_handle, data);
                  }
              });
            return prov_sess_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get credential doscovery request
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDiscResponse (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            cre_disc_req = (CredentialDiscoveryRequestDecoder) client_xml_cache.parse (xmldata);
            CredentialDiscoveryResponseEncoder cdre = new CredentialDiscoveryResponseEncoder (cre_disc_req);
            for (CredentialDiscoveryRequestDecoder.LookupSpecifier ls : cre_disc_req.getLookupSpecifiers ())
              {
                CredentialDiscoveryResponseEncoder.LookupResult lr = cdre.addLookupResult (ls.getID ());
                EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
                while ((eps = sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), false)) != null)
                  {
                    if (ls.getKeyManagementKey ().equals (eps.getKeyManagementKey ()))
                      {
                        EnumeratedKey ek = new EnumeratedKey ();
                        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
                          {
                            if (ek.getProvisioningHandle () == eps.getProvisioningHandle ())
                              {
                                KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                                X509Certificate[] cert_path = ka.getCertificatePath ();
                                CertificateFilter cf = new CertificateFilter ();
                                cf.setSubjectRegEx (ls.getSubjectRegEx ());
                                cf.setSerial (ls.getSerial ());
                                cf.setEmailAddress (ls.getEmailAddress ());
                                cf.setPolicy (ls.getPolicy ());
                                if (!cf.matches (cert_path, null, null))
                                  {
                                    continue;
                                  }
                                lr.addMatchingCredential (HashAlgorithms.SHA256.digest (cert_path[0].getEncoded ()),
                                                          eps.getClientSessionID (),
                                                          eps.getServerSessionID (),
                                                          sks.getKeyProtectionInfo (ek.getKeyHandle ()).isPINBlocked ());
                              }
                          }
                      }
                  }
              }
            return cdre.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get key initialization request and respond with freshly generated public keys
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] KeyInitResponse (byte[] xmldata) throws IOException
          {
            key_init_request = (KeyCreationRequestDecoder) client_xml_cache.parse (xmldata);
            KeyCreationResponseEncoder key_init_response = 
                  new KeyCreationResponseEncoder (key_init_request);
            int pin_policy_handle = 0;
            int puk_policy_handle = 0;
            for (KeyCreationRequestDecoder.KeyObject key : key_init_request.getKeyObjects ())
              {
                byte[] pin_value = key.getPresetPIN ();
                if (key.getPINPolicy () == null)
                  {
                    pin_policy_handle = 0;
                    puk_policy_handle = 0;
                  }
                else
                  {
                    if (key.getPINPolicy ().getUserDefinedFlag ())
                      {
                        pin_value = USER_DEFINED_PIN;
                      }
                    if (key.isStartOfPINPolicy ())
                      {
                        if (key.isStartOfPUKPolicy ())
                          {
                            KeyCreationRequestDecoder.PUKPolicy puk_policy = key.getPINPolicy ().getPUKPolicy ();
                            puk_policy_handle = sks.createPUKPolicy (provisioning_handle, 
                                                                     puk_policy.getID (),
                                                                     puk_policy.getEncryptedValue (),
                                                                     puk_policy.getFormat ().getSKSValue (),
                                                                     puk_policy.getRetryLimit (),
                                                                     puk_policy.getMAC());
                          }
                        KeyCreationRequestDecoder.PINPolicy pin_policy = key.getPINPolicy ();
                        pin_policy_handle = sks.createPINPolicy (provisioning_handle,
                                                                 pin_policy.getID (),
                                                                 puk_policy_handle,
                                                                 pin_policy.getUserDefinedFlag (),
                                                                 pin_policy.getUserModifiableFlag (),
                                                                 pin_policy.getFormat ().getSKSValue (),
                                                                 pin_policy.getRetryLimit (),
                                                                 pin_policy.getGrouping ().getSKSValue (),
                                                                 PatternRestriction.getSKSValue (pin_policy.getPatternRestrictions ()),
                                                                 pin_policy.getMinLength (),
                                                                 pin_policy.getMaxLength (),
                                                                 pin_policy.getInputMethod ().getSKSValue (),
                                                                 pin_policy.getMAC ());
                      }
                  }
                KeyData key_data = sks.createKeyEntry (provisioning_handle,
                                                       key.getID (),
                                                       key_init_request.getAlgorithm (),
                                                       key.getServerSeed (),
                                                       key.isDevicePINProtected (),
                                                       pin_policy_handle,
                                                       pin_value,
                                                       key.getEnablePINCachingFlag (),
                                                       key.getBiometricProtection ().getSKSValue (),
                                                       key.getExportProtection ().getSKSValue (),
                                                       key.getDeleteProtection ().getSKSValue (),
                                                       key.getAppUsage ().getSKSValue (),
                                                       key.getFriendlyName (),
                                                       key.getPrivateKeyBackupFlag (),
                                                       key.getKeySpecifier ().getSKSValue (),
                                                       key.getEndorsedAlgorithms (),
                                                       key.getMAC ());
                key_init_response.addPublicKey (key_data.getPublicKey (),
                                                key_data.getAttestation (),
                                                key.getID (),
                                                key_data.getPrivateKey ());
              }
            return key_init_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get the certificates and attributes and return a success message
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creFinalizeResponse (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            ProvisioningFinalizationRequestDecoder fin_prov_request =
                           (ProvisioningFinalizationRequestDecoder) client_xml_cache.parse (xmldata);
            /* 
               Note: we could have used the saved provisioning_handle but that would not
               work for certifications that are delayed.  The following code is working
               for fully interactive and delayed scenarios by using SKS as state-holder
            */
            EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
            while (true)
              {
                if ((eps = sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), true)) == null)
                  {
                    abort ("Provisioning session not found:" + 
                        fin_prov_request.getClientSessionID () + "/" +
                        fin_prov_request.getServerSessionID ());
                  }
                if (eps.getClientSessionID ().equals(fin_prov_request.getClientSessionID ()) &&
                    eps.getServerSessionID ().equals (fin_prov_request.getServerSessionID ()))
                  {
                    break;
                  }
              }
            
            //////////////////////////////////////////////////////////////////////////
            // Final check, do these keys match the request?
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.DeployedKeyEntry key : fin_prov_request.getDeployedKeyEntrys ())
              {
                int key_handle = sks.getKeyHandle (eps.getProvisioningHandle (), key.getID ());
                sks.setCertificatePath (key_handle, key.getCertificatePath (), key.getMAC ());

                //////////////////////////////////////////////////////////////////////////
                // There may be a symmetric key
                //////////////////////////////////////////////////////////////////////////
                if (key.getEncryptedSymmetricKey () != null)
                  {
                    sks.setSymmetricKey (key_handle, 
                                         key.getEncryptedSymmetricKey (),
                                         key.getSymmetricKeyMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be a private key
                //////////////////////////////////////////////////////////////////////////
                if (key.getEncryptedPrivateKey () != null)
                  {
                    sks.restorePrivateKey (key_handle, 
                                           key.getEncryptedPrivateKey (),
                                           key.getPrivateKeyMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be extensions
                //////////////////////////////////////////////////////////////////////////
                for (ProvisioningFinalizationRequestDecoder.Extension extension : key.getExtensions ())
                  {
                    sks.addExtension (key_handle,
                                      extension.getExtensionType (),
                                      extension.getSubType (), 
                                      extension.getQualifier (),
                                      extension.getExtensionData (),
                                      extension.getMAC ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be an pp_updateKey or pp_cloneKeyProtection
                //////////////////////////////////////////////////////////////////////////
                ProvisioningFinalizationRequestDecoder.PostOperation post_operation = key.getPostOperation ();
                if (post_operation != null)
                  {
                    postProvisioning (post_operation, key_handle);
                  }
              }

            //////////////////////////////////////////////////////////////////////////
            // There may be any number of pp_unlockKey
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.PostOperation pp_unl : fin_prov_request.getPostProvisioningUnlockKeys ())
              {
                postProvisioning (pp_unl, eps.getProvisioningHandle ());
              }

            //////////////////////////////////////////////////////////////////////////
            // There may be any number of pp_deleteKey
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.PostOperation pp_del : fin_prov_request.getPostProvisioningDeleteKeys ())
              {
                postProvisioning (pp_del, eps.getProvisioningHandle ());
              }

            //////////////////////////////////////////////////////////////////////////
            // Create final and attested message
            //////////////////////////////////////////////////////////////////////////
            ProvisioningFinalizationResponseEncoder fin_prov_response = 
                      new ProvisioningFinalizationResponseEncoder (fin_prov_request,
                                                               sks.closeProvisioningSession (eps.getProvisioningHandle (),
                                                                                             fin_prov_request.getCloseSessionNonce (),
                                                                                             fin_prov_request.getCloseSessionMAC ()));
            return fin_prov_response.writeXML ();
          }
      }
    
    class Server
      {
        static final String PLATFORM_URI = "http://issuer.example.com/platform";

        static final String ISSUER_URI = "http://issuer.example.com/provsess";
        
        static final String KEY_INIT_URL = "http://issuer.example.com/keyinit";

        static final String FIN_PROV_URL = "http://issuer.example.com/finalize";

        static final String CRE_DISC_URL = "http://issuer.example.com/credisc";

        static final String LOGO_URL = "http://issuer.example.com/images/logo.png";
        static final String LOGO_MIME = "image/png";
        byte[] LOGO_SHA256 = {0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6}; 
        static final int LOGO_WIDTH = 200;
        static final int LOGO_HEIGHT = 150;
        
        XMLSchemaCache server_xml_cache;
        
        ServerCredentialStore.PINPolicy pin_policy;

        ServerCredentialStore.PUKPolicy puk_policy;
        
        byte[] predef_server_pin = {'3','1','2','5','8','9'};
        
        byte[] bad_pin = {0x03, 0x33, 0x03, 0x04};
        
        int pin_retry_limit = 3;

        PlatformNegotiationRequestEncoder platform_request;

        KeyCreationRequestEncoder key_init_request;
        
        ProvisioningInitializationRequestEncoder prov_sess_request;

        ProvisioningInitializationResponseDecoder prov_sess_response;
        
        ServerCredentialStore server_credential_store;
        
        PrivateKey gen_private_key;
        
        PublicKey server_km;
        
        String server_session_id;

        class SoftHSM implements ServerCryptoInterface
          {
            ////////////////////////////////////////////////////////////////////////////////////////
            // Private and secret keys would in a HSM implementation be represented as handles
            ////////////////////////////////////////////////////////////////////////////////////////
            LinkedHashMap<PublicKey,PrivateKey> key_management_keys = new LinkedHashMap<PublicKey,PrivateKey> ();
            
            private void addKMK (KeyStore km_keystore) throws IOException, GeneralSecurityException
              {
                key_management_keys.put (km_keystore.getCertificate ("mykey").getPublicKey (),
                                         (PrivateKey) km_keystore.getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
              }
            
            SoftHSM () throws IOException, GeneralSecurityException
              {
                addKMK (DemoKeyStore.getMybankDotComKeyStore ());
                addKMK (DemoKeyStore.getSubCAKeyStore ());
                addKMK (DemoKeyStore.getECDSAStore ());
              }
            
            ECPrivateKey server_ec_private_key;
            
            byte[] session_key;
  
            @Override
            public ECPublicKey generateEphemeralKey () throws IOException, GeneralSecurityException
              {
                KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
                ECGenParameterSpec eccgen = new ECGenParameterSpec (ECDomains.P_256.getJCEName ());
                generator.initialize (eccgen, new SecureRandom ());
                java.security.KeyPair kp = generator.generateKeyPair();
                server_ec_private_key = (ECPrivateKey) kp.getPrivate ();
                return (ECPublicKey) kp.getPublic ();
              }

            @Override
            public void generateAndVerifySessionKey (ECPublicKey client_ephemeral_key,
                                                     byte[] kdf_data,
                                                     byte[] session_key_mac_data,
                                                     X509Certificate device_certificate,
                                                     byte[] session_attestation) throws IOException, GeneralSecurityException
              {

                // SP800-56A C(2, 0, ECC CDH)
                KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDH");
                key_agreement.init (server_ec_private_key);
                key_agreement.doPhase (client_ephemeral_key, true);
                byte[] Z = key_agreement.generateSecret ();

                // The custom KDF
                Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
                mac.init (new SecretKeySpec (Z, "RAW"));
                session_key = mac.doFinal (kdf_data);
                
                // The session key signature
                mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
                mac.init (new SecretKeySpec (session_key, "RAW"));
                byte[] session_key_attest = mac.doFinal (session_key_mac_data);
                
                PublicKey device_public_key = device_certificate.getPublicKey ();
                SignatureAlgorithms signature_algorithm = device_public_key instanceof RSAPublicKey ?
                    SignatureAlgorithms.RSA_SHA256 : SignatureAlgorithms.ECDSA_SHA256;

                // Verify that the session key signature was signed by the device key
                Signature verifier = Signature.getInstance (signature_algorithm.getJCEName ());
                verifier.initVerify (device_public_key);
                verifier.update (session_key_attest);
                if (!verifier.verify (session_attestation))
                  {
                    throw new IOException ("Verify provisioning signature failed");
                  }
              }

            @Override
            public byte[] mac (byte[] data, byte[] key_modifier) throws IOException, GeneralSecurityException
              {
                Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
                mac.init (new SecretKeySpec (ArrayUtil.add (session_key, key_modifier), "RAW"));
                return mac.doFinal (data);
              }

            @Override
            public byte[] decrypt (byte[] data) throws IOException, GeneralSecurityException
              {
                byte[] key = mac (SecureKeyStore.KDF_ENCRYPTION_KEY, new byte[0]);
                Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
                crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (data, 0, 16));
                return crypt.doFinal (data, 16, data.length - 16);
              }

            @Override
            public byte[] encrypt (byte[] data) throws IOException, GeneralSecurityException
              {
                byte[] key = mac (SecureKeyStore.KDF_ENCRYPTION_KEY, new byte[0]);
                Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
                byte[] iv = new byte[16];
                new SecureRandom ().nextBytes (iv);
                crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
                return ArrayUtil.add (iv, crypt.doFinal (data));
              }

            @Override
            public byte[] generateNonce () throws IOException, GeneralSecurityException
              {
                byte[] rnd = new byte[32];
                new SecureRandom ().nextBytes (rnd);
                return rnd;
              }

            @Override
            public byte[] generateKeyManagementAuthorization (PublicKey key_management__key, byte[] data) throws IOException, GeneralSecurityException
              {
                Signature km_sign = Signature.getInstance (key_management__key instanceof RSAPublicKey ? "SHA256WithRSA" : "SHA256WithECDSA");
                km_sign.initSign (key_management_keys.get (key_management__key));
                km_sign.update (data);
                return km_sign.sign ();
              }

            @Override
            public PublicKey[] enumerateKeyManagementKeys () throws IOException, GeneralSecurityException
              {
                return key_management_keys.keySet ().toArray (new PublicKey[0]);
              }
          }
        
        SoftHSM server_sess_key = new SoftHSM ();

        Server () throws Exception
          {
            server_xml_cache = new XMLSchemaCache ();
            server_xml_cache.addWrapper (PlatformNegotiationResponseDecoder.class);
            server_xml_cache.addWrapper (ProvisioningInitializationResponseDecoder.class);
            server_xml_cache.addWrapper (CredentialDiscoveryResponseDecoder.class);
            server_xml_cache.addWrapper (KeyCreationResponseDecoder.class);
            server_xml_cache.addWrapper (ProvisioningFinalizationResponseDecoder.class);
          }
        
        void getProvSess (XMLObjectWrapper xml_object) throws IOException
          {
            ////////////////////////////////////////////////////////////////////////////////////
            // Begin with creating the "SessionKey" that holds just about everything
            ////////////////////////////////////////////////////////////////////////////////////
            prov_sess_response = (ProvisioningInitializationResponseDecoder) xml_object;
            prov_sess_response.verifyAndGenerateSessionKey (server_sess_key,
                                                            prov_sess_request,
                                                            https ? server_certificate : null);

            ////////////////////////////////////////////////////////////////////////////////////
            // Here we could/should introduce an SKS identity/brand check
            ////////////////////////////////////////////////////////////////////////////////////
            X509Certificate[] certificate_path = prov_sess_response.getDeviceCertificatePath ();

            ////////////////////////////////////////////////////////////////////////////////////
            // Now we can create the container
            ////////////////////////////////////////////////////////////////////////////////////
            server_credential_store = new ServerCredentialStore (prov_sess_response, prov_sess_request);

          }
        
        void verifyPrivateKeyBackup (ServerCredentialStore.KeyProperties key_prop) throws IOException, GeneralSecurityException
          {
            PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (server_sess_key.decrypt (key_prop.getBackupPrivateKey ()));
            boolean rsa = key_prop.getPublicKey () instanceof RSAPublicKey;
            PrivateKey private_key = KeyFactory.getInstance (rsa ? "RSA" : "EC").generatePrivate (key_spec);
            Signature sign = Signature.getInstance ((rsa ? SignatureAlgorithms.RSA_SHA256 : SignatureAlgorithms.ECDSA_SHA256).getJCEName ());
            sign.initSign (private_key);
            sign.update (TEST_STRING);
            byte[] key_archival_verify = sign.sign ();
            Signature verify = Signature.getInstance ((rsa ? SignatureAlgorithms.RSA_SHA256 : SignatureAlgorithms.ECDSA_SHA256).getJCEName ());
            verify.initVerify (key_prop.getPublicKey ());
            verify.update (TEST_STRING);
            if (!verify.verify (key_archival_verify))
              {
                throw new GeneralSecurityException ("Archived private key validation failed");
              }
          }

        //////////////////////////////////////////////////////////////////////////////////
        // Create platform negotiation request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] platformRequest () throws IOException, GeneralSecurityException
          {
            server_session_id = "S-" + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());
            platform_request =  new PlatformNegotiationRequestEncoder (server_session_id, PLATFORM_URI);
            platform_request.addLogotype (LOGO_URL, LOGO_MIME, LOGO_SHA256, LOGO_WIDTH, LOGO_HEIGHT);
            if (ask_for_4096)
              {
                platform_request.getBasicCapabilities ().addRSAKeySize ((short)4096).addRSAKeySize ((short)2048);
              }
            if (plain_unlock_key != null)
              {
                platform_request.setAction (Action.UNLOCK);
              }
            return platform_request.writeXML ();
          }

        //////////////////////////////////////////////////////////////////////////////////
        // Create a provisioning session request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] provSessRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            PlatformNegotiationResponseDecoder platform_response = (PlatformNegotiationResponseDecoder) server_xml_cache.parse (xmldata);
            prov_sess_request =  new ProvisioningInitializationRequestEncoder (server_sess_key.generateEphemeralKey (),
                                                                               server_session_id,
                                                                               ISSUER_URI,
                                                                               10000,
                                                                               (short)50);
            if (updatable)
              {
                prov_sess_request.setKeyManagementKey(server_km = server_sess_key.enumerateKeyManagementKeys ()[ecc_kmk ? 2 : 0]);
              }
            return prov_sess_request.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create credential discover request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDiscRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            getProvSess (server_xml_cache.parse (xmldata));
            CredentialDiscoveryRequestEncoder cdre = new CredentialDiscoveryRequestEncoder (prov_sess_response, CRE_DISC_URL);
            cdre.addLookupDescriptor (server_sess_key, server_sess_key.enumerateKeyManagementKeys ()[0]);
            cdre.addLookupDescriptor (server_sess_key, server_sess_key.enumerateKeyManagementKeys ()[2]).setEmailAddress ("john.doe@example.com");
            cdre.addLookupDescriptor (server_sess_key, server_sess_key.enumerateKeyManagementKeys ()[2]).setEmailAddress ("jane.doe@example.com");
            cdre.addLookupDescriptor (server_sess_key, server_sess_key.enumerateKeyManagementKeys ()[1])
                          .setEmailAddress ("john.doe@example.com")
                          .setExcludedPolicies (new String[]{"1.3.4","34.90"})
                          .setPolicy ("5.4.8")
                          .setSerial (new BigInteger ("123"))
                          .setIssuedBefore (new Date (new Date ().getTime () - 100000))
                          .setIssuedAfter (new Date ())
                          .setSubjectRegEx ("CN=John");
            return cdre.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create a key init request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] keyInitRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            XMLObjectWrapper xml_object = server_xml_cache.parse (xmldata);
            if (xml_object instanceof ProvisioningInitializationResponseDecoder)
              {
                getProvSess (xml_object);
              }
            else
              {
                CredentialDiscoveryResponseDecoder cdrd = (CredentialDiscoveryResponseDecoder) xml_object;
                CredentialDiscoveryResponseDecoder.LookupResult[] lres = cdrd.getLookupResults ();
// TODO verify
              }

            if (puk_protection)
              {
                puk_policy =
                  server_credential_store.createPUKPolicy (server_sess_key.encrypt (new byte[]{'0','1','2','3','4','5','6', '7','8','9'}),
                                                                                    PassphraseFormat.NUMERIC,
                                                                                    3);
              }
            if (pin_protection)
              {
                pin_policy = server_credential_store.createPINPolicy (PassphraseFormat.NUMERIC,
                                                                      4,
                                                                      8,
                                                                      pin_retry_limit,
                                                                      puk_policy);
                if (add_pin_pattern)
                  {
                    pin_policy.addPatternRestriction (PatternRestriction.THREE_IN_A_ROW);
                    pin_policy.addPatternRestriction (PatternRestriction.SEQUENCE);
                  }
                if (pin_group_shared)
                  {
                    pin_policy.setGrouping (Grouping.SHARED);
                  }
                if (input_method != null)
                  {
                    pin_policy.setInputMethod (input_method);
                  }
              }
            KeySpecifier key_alg =  ecc_key ?
                 new KeySpecifier.EC (ECDomains.P_256) : new KeySpecifier.RSA (2048);

            ServerCredentialStore.KeyProperties kp = device_pin_protection ?
                server_credential_store.createDevicePINProtectedKey (AppUsage.AUTHENTICATION, key_alg) :
                  preset_pin ? server_credential_store.createKeyWithPresetPIN (encryption_key ? AppUsage.ENCRYPTION : AppUsage.AUTHENTICATION,
                                                                               key_alg, pin_policy,
                                                                               server_sess_key.encrypt (predef_server_pin))
                             :
                server_credential_store.createKey (encryption_key || key_agreement? AppUsage.ENCRYPTION : AppUsage.AUTHENTICATION,
                                                   key_alg,
                                                   pin_policy);
            if (symmetric_key || encryption_key)
              {
                kp.setEndorsedAlgorithms (new String[]{encryption_key ? SymEncryptionAlgorithms.AES256_CBC.getURI () : MacAlgorithms.HMAC_SHA1.getURI ()});
                kp.setEncryptedSymmetricKey (server_sess_key.encrypt (encryption_key ? AES32BITKEY : OTP_SEED));
              }
            if (key_agreement)
              {
                kp.setEndorsedAlgorithms (new String[]{KeyGen2URIs.ALGORITHMS.ECDH});
              }
            if (property_bag)
              {
                kp.addPropertyBag ("http://host/prop")
                  .addProperty ("main", "234", false)
                  .addProperty ("a", "fun", true);
              }
            if (encrypted_extension)
              {
                kp.addEncryptedExtension ("http://host/ee", server_sess_key.encrypt (new byte[]{0,5}));
              }
            if (private_key_backup)
              {
                kp.setPrivateKeyBackup (true);
              }
            if (export_protection != null)
              {
                kp.setExportProtection (export_protection);
              }
            if (delete_protection != null)
              {
                kp.setDeleteProtection (delete_protection);
              }
            if (server_seed)
              {
                byte[] seed = new byte[32];
                new SecureRandom ().nextBytes (seed);
                kp.setServerSeed (seed);
              }
            if (clone_key_protection != null)
              {
                kp.setClonedKeyProtection (clone_key_protection.server_credential_store.getClientSessionID (), 
                                           clone_key_protection.server_credential_store.getServerSessionID (),
                                           clone_key_protection.server_credential_store.getKeyProperties ().toArray (new ServerCredentialStore.KeyProperties[0])[0].getCertificatePath ()[0],
                                           clone_key_protection.server_km);
              }
            if (update_key != null)
              {
                kp.setUpdatedKey (update_key.server_credential_store.getClientSessionID (), 
                                  update_key.server_credential_store.getServerSessionID (),
                                  update_key.server_credential_store.getKeyProperties ().toArray (new ServerCredentialStore.KeyProperties[0])[0].getCertificatePath ()[0],
                                  update_key.server_km);
              }
            if (delete_key != null)
              {
                server_credential_store.addPostProvisioningDeleteKey (delete_key.server_credential_store.getClientSessionID (), 
                                                                      delete_key.server_credential_store.getServerSessionID (),
                                                                      delete_key.server_credential_store.getKeyProperties ().toArray (new ServerCredentialStore.KeyProperties[0])[0].getCertificatePath ()[0],
                                                                      delete_key.server_km);
              }
            key_init_request = new KeyCreationRequestEncoder (KEY_INIT_URL, server_credential_store, server_sess_key);
            return key_init_request.writeXML ();
          }


        ///////////////////////////////////////////////////////////////////////////////////
        // Get the key init response and respond with certified public keys and attributes
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creFinalizeRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            if (plain_unlock_key == null)
              {
                KeyCreationResponseDecoder key_init_response = (KeyCreationResponseDecoder) server_xml_cache.parse (xmldata);
                key_init_response.validateAndPopulate (key_init_request, server_sess_key);
                for (ServerCredentialStore.KeyProperties key_prop : server_credential_store.getKeyProperties ())
                  {
                    if (key_prop.getPrivateKeyBackupFlag ())
                      {
                        verifyPrivateKeyBackup (key_prop);
                      }
                    boolean otp = symmetric_key && !encryption_key;
                    boolean auth = key_prop.getAppUsage () == AppUsage.AUTHENTICATION;
                    CertSpec cert_spec = new CertSpec ();
                    if (!otp)
                      {
                        // OTP certificates are just for transport
                        cert_spec.setEndEntityConstraint ();
                        if (auth)
                          {
                            cert_spec.setKeyUsageBit (KeyUsageBits.digitalSignature);
                            cert_spec.setKeyUsageBit (KeyUsageBits.keyAgreement);
                          }
                        else
                          {
                            cert_spec.setKeyUsageBit (KeyUsageBits.dataEncipherment);
                            cert_spec.setKeyUsageBit (KeyUsageBits.keyEncipherment);
                          }
                      }
                    cert_spec.setSubject ("CN=JUnit " + _name.getMethodName() + ", E=john.doe@example.com" +
                                          (otp ? ", OU=OTP Key" : ""));
    
                    GregorianCalendar start = new GregorianCalendar ();
                    GregorianCalendar end = (GregorianCalendar) start.clone ();
                    end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);
    
                    PublicKey pub_key =  key_prop.getPublicKey ();
    
                    if (set_private_key)
                      {
                        KeyPairGenerator generator = KeyPairGenerator.getInstance (ecc_key ? "EC" :"RSA");
                        if (ecc_key)
                          {
                            generator.initialize (new ECGenParameterSpec ("P-256"), new SecureRandom ());
                          }
                        else
                          {
                            generator.initialize (new RSAKeyGenParameterSpec (1024, RSAKeyGenParameterSpec.F4), new SecureRandom ());
                          }
                        java.security.KeyPair kp = generator.generateKeyPair();
                        pub_key = kp.getPublic ();
                        gen_private_key = kp.getPrivate ();
                      }
    
                    X509Certificate certificate = 
                        new CA ().createCert (cert_spec,
                                              DistinguishedName.subjectDN ((X509Certificate)DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey")),
                                              new BigInteger (String.valueOf (new Date ().getTime ())),
                                              start.getTime (),
                                              end.getTime (), 
                                              SignatureAlgorithms.RSA_SHA256,
                                              new AsymKeySignerInterface ()
                        {
    
                          @Override
                          public PublicKey getPublicKey () throws IOException, GeneralSecurityException
                            {
                              return ((X509Certificate)DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey")).getPublicKey ();
                            }
    
                          @Override
                          public byte[] signData (byte[] data, SignatureAlgorithms algorithm) throws IOException, GeneralSecurityException
                            {
                              Signature signer = Signature.getInstance (algorithm.getJCEName ());
                              signer.initSign ((PrivateKey) DemoKeyStore.getSubCAKeyStore ().getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
                              signer.update (data);
                              return signer.sign ();
                            }
                          
                        }, pub_key);
                    key_prop.setCertificatePath (new X509Certificate[]{certificate});
    
                    if (set_private_key)
                      {
                        key_prop.setEncryptedPrivateKey (server_sess_key.encrypt (gen_private_key.getEncoded ()));
                      }
    
                  }
              }
            else
              {
                server_credential_store.addPostProvisioningUnlockKey (plain_unlock_key.server_credential_store.getClientSessionID (), 
                                                                      plain_unlock_key.server_credential_store.getServerSessionID (),
                                                                      plain_unlock_key.server_credential_store.getKeyProperties ().toArray (new ServerCredentialStore.KeyProperties[0])[0].getCertificatePath ()[0],
                                                                      plain_unlock_key.server_km);
              }
            ProvisioningFinalizationRequestEncoder fin_prov_request 
                           = new ProvisioningFinalizationRequestEncoder (FIN_PROV_URL, 
                                                                     server_credential_store,
                                                                     server_sess_key);

            return fin_prov_request.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally we get the attestested response
        ///////////////////////////////////////////////////////////////////////////////////
        void creFinalizeResponse (byte[] xmldata) throws IOException
          {
            ProvisioningFinalizationResponseDecoder fin_prov_response = (ProvisioningFinalizationResponseDecoder) server_xml_cache.parse (xmldata);
            fin_prov_response.verifyProvisioningResult (server_credential_store, server_sess_key);
          }
      }
    
    class Doer
      {
        Server server;
        Client client;
        XMLSchemaCache xmlschemas = new XMLSchemaCache ();
        int pass;
        
        private void write (byte[] data) throws Exception
          {
            if (fos != null)
              {
                for (int i = 0; i < data.length; i++)
                  {
                    byte b = data[i];
                    if (b == '\n' && html_mode)
                      {
                        fos.write ("<br>".getBytes ("UTF-8"));
                      }
                    else
                      {
                        fos.write (b);
                      }
                  }
              }
          }
        
        private void write (int b) throws Exception
          {
            write (new byte[]{(byte)b}); 
          }
        
        private void writeString (String message) throws Exception
          {
            write (message.getBytes ("UTF-8"));
          }
        
        private void writeOption (String option, boolean writeit) throws Exception
          {
            if (writeit)
              {
                writeString (option);
                write ('\n');
              }
          }
        
        byte[] fileLogger (byte[] xmldata) throws Exception
          {
            XMLObjectWrapper xo = xmlschemas.parse (xmldata);
            if (html_mode)
              {
                writeString ("&nbsp;<br><table><tr><td bgcolor=\"#F0F0F0\" style=\"border:solid;border-width:1px;padding:4px\">&nbsp;Pass #" + (++pass) + ":&nbsp;" + xo.element () + "&nbsp;</td></tr></table>&nbsp;<br>");
                writeString (XML2HTMLPrinter.convert (new String (xmldata, "UTF-8")));
              }
            else
              {
                String element = "#" + (++pass) + ": " + xo.element ();
                write ('\n');
                for (int i = 0; i < element.length (); i++) write ('-');
                write ('\n');
                writeString (element);
                write ('\n');
                for (int i = 0; i < element.length (); i++) write ('-');
                write ('\n');
                write ('\n');
                write (xmldata);
                write ('\n');
              }
            return xmldata;
          }

        
        Doer () throws Exception
          {
            xmlschemas.addWrapper (PlatformNegotiationRequestDecoder.class);
            xmlschemas.addWrapper (PlatformNegotiationResponseDecoder.class);
            xmlschemas.addWrapper (ProvisioningInitializationRequestDecoder.class);
            xmlschemas.addWrapper (ProvisioningInitializationResponseDecoder.class);
            xmlschemas.addWrapper (CredentialDiscoveryRequestDecoder.class);
            xmlschemas.addWrapper (CredentialDiscoveryResponseDecoder.class);
            xmlschemas.addWrapper (KeyCreationRequestDecoder.class);
            xmlschemas.addWrapper (KeyCreationResponseDecoder.class);
            xmlschemas.addWrapper (ProvisioningFinalizationRequestDecoder.class);
            xmlschemas.addWrapper (ProvisioningFinalizationResponseDecoder.class);
          }
        
        void perform () throws Exception
          {
            if (html_mode)
              {
                writeString ("<b>");
              }
            writeString ("Begin Test (" + _name.getMethodName() + ":" + (++round) + (html_mode ? ")</b><br>" : ")\n"));
            writeOption ("4096 over 2048 RSA key preference", ask_for_4096);
            writeOption ("Client shows one image preference", image_prefs);
            writeOption ("PUK Protection", puk_protection);
            writeOption ("PIN Protection ", pin_protection);
            writeOption ("PIN Input Method ", input_method != null);
            writeOption ("Device PIN", device_pin_protection);
            writeOption ("Preset PIN", preset_pin);
            writeOption ("PIN patterns", add_pin_pattern);
            writeOption ("ECC Key", ecc_key);
            writeOption ("Server Seed", server_seed);
            writeOption ("PropertyBag", property_bag);
            writeOption ("Symmetric Key", symmetric_key);
            writeOption ("Encryption Key", encryption_key);
            writeOption ("Encrypted Extension", encrypted_extension);
            writeOption ("Private Key Backup", private_key_backup);
            writeOption ("Delete Protection", delete_protection != null);
            writeOption ("Export Protection", export_protection != null);
            writeOption ("Private Key Restore", set_private_key);
            writeOption ("Updatable session", updatable);
            writeOption ("CloneKeyProtection", clone_key_protection != null);
            writeOption ("UpdateKey", update_key != null);
            writeOption ("DeleteKey", delete_key != null);
            writeOption ("UnlockKey", plain_unlock_key != null);
            writeOption ("ECC KMK", ecc_kmk);
            writeOption ("HTTPS server certificate", https);
            server = new Server ();
            client = new Client ();
            byte[] xml;
            xml = fileLogger (server.platformRequest ());
            xml = fileLogger (client.platformResponse (xml));
            xml = fileLogger (server.provSessRequest (xml));
            xml = fileLogger (client.provSessResponse (xml));
            if (delete_key != null || clone_key_protection != null || update_key != null || plain_unlock_key != null)
              {
                xml = fileLogger (server.creDiscRequest (xml));
                xml = fileLogger (client.creDiscResponse (xml));
              }
            if (plain_unlock_key == null)
              {
                xml = fileLogger (server.keyInitRequest (xml));
                xml = fileLogger (client.KeyInitResponse (xml));
              }
            xml = fileLogger (server.creFinalizeRequest (xml));
            xml = fileLogger (client.creFinalizeResponse (xml));
            server.creFinalizeResponse (xml);
            writeString ("\n");
            EnumeratedKey ek = new EnumeratedKey ();
            while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
              {
                if (ek.getProvisioningHandle () == client.provisioning_handle)
                  {
                    KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                    writeString ("Deployed key[" + ek.getKeyHandle () + "] " + CertificateUtil.convertRFC2253ToLegacy (ka.getCertificatePath ()[0].getSubjectX500Principal ().getName ()) + "\n");
                  }
              }
            writeString ("\n\n");
         }
        
      }

    @Test
    public void CryptoPreferences () throws Exception
      {
        ask_for_4096 = true;
        new Doer ().perform ();
      }

    @Test
    public void ImagePreferences () throws Exception
      {
        Doer doer = new Doer ();
        image_prefs = true;
        pin_protection = true;
        doer.perform ();
      }

    @Test
    public void PINPatterns () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        add_pin_pattern = true;
        ecc_key = true;
        https = true;
        doer.perform ();
      }

    @Test
    public void ServerCertificate () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        ecc_key = true;
        https = true;
        doer.perform ();
      }

    @Test
    public void ServerSeed () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        server_seed = true;
        doer.perform ();
      }

    @Test
    public void PrivateKeyBackup () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        private_key_backup = true;
        doer.perform ();
      }

    @Test
    public void EncryptedExtension () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        ecc_key = true;
        property_bag = true;
        encrypted_extension = true;
        server_seed = true;
        doer.perform ();
      }

    @Test
    public void InputMethod () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        puk_protection = true;
        input_method = InputMethod.PROGRAMMATIC;
        doer.perform ();
      }

    @Test
    public void PropertyBag () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        symmetric_key = true;
        property_bag = true;
        doer.perform ();
        ServerCredentialStore.PropertyBag prop_bag = doer.server.server_credential_store.getKeyProperties ().toArray (new ServerCredentialStore.KeyProperties[0])[0].getPropertyBags ()[0];
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getProvisioningHandle () == doer.client.provisioning_handle)
              {
                j++;
                Property[] props1 = sks.getExtension (ek.getKeyHandle (), prop_bag.getType ()).getProperties ();
                ServerCredentialStore.Property[] props2 = prop_bag.getProperties ();
                assertTrue ("Prop len error", props1.length == props2.length);
                int w = 0;
                for (int i = 0; i < props1.length; i++)
                  {
                    if (props2[i].isWritable ())
                      {
                        w = i;
                      }
                    assertTrue ("Prop name error", props1[i].getName ().equals (props2[i].getName ()));
                    assertTrue ("Prop value error", props1[i].getValue ().equals (props2[i].getValue ()));
                  }
                sks.setProperty (ek.getKeyHandle (), prop_bag.getType (), props2[w].getName ().getBytes ("UTF-8"), (props2[w].getValue () + "w2").getBytes ("UTF-8"));
                props1 = sks.getExtension (ek.getKeyHandle (), prop_bag.getType ()).getProperties ();
                for (int i = 0; i < props1.length; i++)
                  {
                    assertTrue ("Prop name error", props1[i].getName ().equals (props2[i].getName ()));
                    assertTrue ("Prop value error", (i == w) ^ props1[i].getValue ().equals (props2[i].getValue ()));
                  }
                sks.setProperty (ek.getKeyHandle (), prop_bag.getType (), props2[w].getName ().getBytes ("UTF-8"), props2[w].getValue ().getBytes ("UTF-8"));
                props1 = sks.getExtension (ek.getKeyHandle (), prop_bag.getType ()).getProperties ();
                for (int i = 0; i < props1.length; i++)
                  {
                    assertTrue ("Prop name error", props1[i].getName ().equals (props2[i].getName ()));
                    assertTrue ("Prop value error", props1[i].getValue ().equals (props2[i].getValue ()));
                  }
                assertTrue ("HMAC error", ArrayUtil.compare (sks.performHMAC (ek.getKeyHandle (), MacAlgorithms.HMAC_SHA1.getURI (), USER_DEFINED_PIN, TEST_STRING),
                                                             MacAlgorithms.HMAC_SHA1.digest (OTP_SEED, TEST_STRING)));
              }
          }
        assertTrue ("Missing keys", j == 1);
      }

    @Test
    public void SymmetricEncryptionKey () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        encryption_key = true;
        symmetric_key = true;
        doer.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getProvisioningHandle () == doer.client.provisioning_handle)
              {
                j++;
                byte[] iv = null;
                byte[] enc = sks.symmetricKeyEncrypt (ek.getKeyHandle (),
                                                      SymEncryptionAlgorithms.AES256_CBC.getURI (),
                                                      true,
                                                      iv,
                                                      USER_DEFINED_PIN,
                                                      TEST_STRING);
                assertTrue ("Encrypt/decrypt error", ArrayUtil.compare (sks.symmetricKeyEncrypt (ek.getKeyHandle (),
                                                                                                 SymEncryptionAlgorithms.AES256_CBC.getURI (),
                                                                                                 false,
                                                                                                 iv,
                                                                                                 USER_DEFINED_PIN, 
                                                                                                 enc),
                                                                                                 TEST_STRING));
              }
          }
        assertTrue ("Missing keys", j == 1);
      }

    @Test
    public void DevicePIN () throws Exception
      {
        Doer doer = new Doer ();
        device_pin_protection = true;
        doer.perform ();
      }

    @Test
    public void PresetPIN () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        preset_pin = true;
        doer.perform ();
      }

    @Test
    public void CloneKeyProtection () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        ecc_kmk = true;
        pin_protection = true;
        pin_group_shared = true;
        preset_pin = true;
        doer1.perform ();
        updatable = false;
        pin_protection = false;
        preset_pin = false;
        clone_key_protection = doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getProvisioningHandle () == doer2.client.provisioning_handle)
              {
                j++;
                KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                byte[] result = sks.signHashedData (ek.getKeyHandle (),
                                                    SignatureAlgorithms.RSA_SHA256.getURI (),
                                                    null,
                                                    doer2.server.predef_server_pin,
                                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
                verify.initVerify (ka.getCertificatePath ()[0]);
                verify.update (TEST_STRING);
                assertTrue ("Bad signature", verify.verify (result));
              }
          }
        assertTrue ("Missing keys", j == 2);
      }

    @Test
    public void UpdateKey () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        pin_protection = true;
        pin_group_shared = true;
        preset_pin = true;
        doer1.perform ();
        updatable = false;
        pin_protection = false;
        preset_pin = false;
        update_key= doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getProvisioningHandle () == doer2.client.provisioning_handle)
              {
                j++;
                KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                byte[] result = sks.signHashedData (ek.getKeyHandle (),
                                                    SignatureAlgorithms.RSA_SHA256.getURI (),
                                                    null,
                                                    doer2.server.predef_server_pin,
                                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
                verify.initVerify (ka.getCertificatePath ()[0]);
                verify.update (TEST_STRING);
                assertTrue ("Bad signature", verify.verify (result));
              }
          }
        assertTrue ("Missing keys", j == 1);
      }

    @Test
    public void DeleteKey () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        doer1.perform ();
        updatable = false;
        delete_key= doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getProvisioningHandle () == doer1.client.provisioning_handle)
              {
                j++;
              }
          }
        assertTrue ("Too many keys", j == 0);
      }

    @Test
    public void SetPrivateKey () throws Exception
      {
        Doer doer = new Doer ();
        set_private_key = true;
        pin_protection = true;
        preset_pin = true;
        doer.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getProvisioningHandle () == doer.client.provisioning_handle)
              {
                j++;
                byte[] result = sks.signHashedData (ek.getKeyHandle (),
                                                    SignatureAlgorithms.RSA_SHA256.getURI (),
                                                    null,
                                                    doer.server.predef_server_pin,
                                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                Signature sign = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
                sign.initSign (doer.server.gen_private_key);
                sign.update (TEST_STRING);
                assertTrue ("Bad signature", ArrayUtil.compare (sign.sign (), result));
              }
          }
        assertTrue ("Missing keys", j == 1);
      }

    @Test
    public void ExportProtection () throws Exception
      {
        for (ExportProtection exp_pol : ExportProtection.values ())
          {
            Doer doer = new Doer ();
            export_protection = exp_pol;
            if (exp_pol == ExportProtection.PIN || exp_pol == ExportProtection.PUK)
              {
                pin_protection = true;
              }
            if (exp_pol == ExportProtection.PUK)
              {
                puk_protection = true;
              }
            ecc_key = true;
            doer.perform ();
          }
      }

    @Test
    public void DeleteProtection () throws Exception
      {
        for (DeleteProtection del_pol : DeleteProtection.values ())
          {
            Doer doer = new Doer ();
            if (del_pol == DeleteProtection.PIN || del_pol == DeleteProtection.PUK)
              {
                pin_protection = true;
              }
            if (del_pol == DeleteProtection.PUK)
              {
                puk_protection = true;
              }
            delete_protection = del_pol;
            ecc_key = true;
            doer.perform ();
          }
      }

    @Test
    public void KeyAgreement () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        ecc_key = true;
        key_agreement = true;
        doer.perform ();
      }

    @Test
    public void UnlockKey () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        pin_protection = true;
        ecc_key = true;
        doer1.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getProvisioningHandle () == doer1.client.provisioning_handle)
              {
                j++;
                break;
              }
          }
        assertTrue ("Missing keys", j == 1);
        for (int i = 1; i <= doer1.server.pin_retry_limit; i++)
          {
            try
              {
                sks.signHashedData (ek.getKeyHandle (),
                                    SignatureAlgorithms.ECDSA_SHA256.getURI (),
                                    null,
                                    doer1.server.bad_pin,
                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                fail ("Bad PIN should not work");
              }
            catch (SKSException e)
              {
                assertFalse ("Locked", sks.getKeyProtectionInfo (ek.getKeyHandle ()).isPINBlocked () ^ (i == doer1.server.pin_retry_limit));
              }
          }

        updatable = false;
        pin_protection = false;
        ecc_key = false;
        plain_unlock_key= doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        assertFalse ("UnLocked", sks.getKeyProtectionInfo (ek.getKeyHandle ()).isPINBlocked ());
      }
  }
