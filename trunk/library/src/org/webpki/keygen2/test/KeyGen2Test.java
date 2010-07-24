/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;
import java.util.GregorianCalendar;
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
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ECDomains;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.keygen2.CredentialDeploymentRequestDecoder;
import org.webpki.keygen2.CredentialDeploymentRequestEncoder;
import org.webpki.keygen2.CredentialDeploymentResponseDecoder;
import org.webpki.keygen2.CredentialDeploymentResponseEncoder;
import org.webpki.keygen2.CryptoConstants;
import org.webpki.keygen2.DeletePolicy;
import org.webpki.keygen2.ExportPolicy;
import org.webpki.keygen2.InputMethod;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyInitializationResponseDecoder;
import org.webpki.keygen2.KeyInitializationResponseEncoder;
import org.webpki.keygen2.KeyUsage;
import org.webpki.keygen2.KeyInitializationRequestDecoder;
import org.webpki.keygen2.KeyInitializationRequestEncoder;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PassphraseFormat;
import org.webpki.keygen2.PatternRestriction;
import org.webpki.keygen2.PlatformNegotiationRequestDecoder;
import org.webpki.keygen2.PlatformNegotiationRequestEncoder;
import org.webpki.keygen2.PlatformNegotiationResponseDecoder;
import org.webpki.keygen2.PlatformNegotiationResponseEncoder;
import org.webpki.keygen2.ProvisioningSessionRequestDecoder;
import org.webpki.keygen2.ProvisioningSessionRequestEncoder;
import org.webpki.keygen2.ProvisioningSessionResponseDecoder;
import org.webpki.keygen2.ProvisioningSessionResponseEncoder;
import org.webpki.keygen2.ServerCredentialStore;
import org.webpki.keygen2.ServerSessionKeyInterface;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyPair;
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
    
    boolean server_seed;
    
    boolean property_bag;
    
    boolean symmetric_key;
    
    boolean updatable;
    
    Server clone_key_protection;
    
    Server update_key;
    
    Server delete_key;
    
    boolean device_pin;
    
    boolean pin_group_shared;
    
    boolean puk_protection;
    
    boolean add_pin_pattern;
    
    boolean preset_pin;
    
    boolean encryption_key;
    
    boolean set_private_key;
    
    boolean encrypted_extension;
    
    boolean ask_for_4096;
    
    ExportPolicy export_policy;
    
    DeletePolicy delete_policy;
    
    InputMethod input_method;
    
    boolean image_prefs;
    
    static FileOutputStream fos;
    
    static SecureKeyStore sks;
    
    static boolean html_mode;

    static final byte[] OTP_SEED = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    
    static final byte[] AES32BITKEY = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    
    static final byte[] USER_DEFINED_PIN = {'0','1','5','3','5','4'};

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
        Security.addProvider(new BouncyCastleProvider());
        sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.implementation")).newInstance ();
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
        
        KeyInitializationRequestDecoder key_init_request;
        
        ProvisioningSessionRequestDecoder prov_sess_req;
        
        DeviceInfo device_info;
        
        Client () throws IOException
          {
            client_xml_cache = new XMLSchemaCache ();
            client_xml_cache.addWrapper (PlatformNegotiationRequestDecoder.class);
            client_xml_cache.addWrapper (ProvisioningSessionRequestDecoder.class);
            client_xml_cache.addWrapper (KeyInitializationRequestDecoder.class);
            client_xml_cache.addWrapper (CredentialDeploymentRequestDecoder.class);
          }

        private void abort (String message) throws IOException, SKSException
          {
            sks.abortProvisioningSession (provisioning_handle);
            throw new IOException (message);
          }
        
        private void postProvisioning (CredentialDeploymentRequestDecoder.PostOperation post_operation, int handle) throws IOException, GeneralSecurityException
          {
            EnumeratedProvisioningSession old_provisioning_session = new EnumeratedProvisioningSession ();
            while (true)
              {
                old_provisioning_session = sks.enumerateProvisioningSessions (old_provisioning_session, false);
                if (!old_provisioning_session.isValid ())
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
                ek = sks.enumerateKeys (ek);
                if (!ek.isValid ())
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
                            case CredentialDeploymentRequestDecoder.PostOperation.CLONE_KEY_PROTECTION:
                              sks.pp_cloneKeyProtection (handle, ek.getKeyHandle (), post_operation.getMAC ());
                              break;

                            case CredentialDeploymentRequestDecoder.PostOperation.UPDATE_KEY:
                              sks.pp_updateKey (handle, ek.getKeyHandle (), post_operation.getMAC ());
                              break;

                            default:
                              sks.pp_deleteKey (handle, ek.getKeyHandle (), post_operation.getMAC ());
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
            prov_sess_req = (ProvisioningSessionRequestDecoder) client_xml_cache.parse (xmldata);
            Date client_time = new Date ();
            ProvisioningSession sess = 
                  sks.createProvisioningSession (prov_sess_req.getSessionKeyAlgorithm (),
                                                 prov_sess_req.getServerSessionID (),
                                                 prov_sess_req.getServerEphemeralKey (),
                                                 prov_sess_req.getSubmitURL (), /* IssuerURI */
                                                 prov_sess_req.getSessionUpdatableFlag (),
                                                 (int)(client_time.getTime () / 1000),
                                                 prov_sess_req.getSessionLifeTime (),
                                                 prov_sess_req.getSessionKeyLimit ());
            provisioning_handle = sess.getProvisioningHandle ();
            
            ProvisioningSessionResponseEncoder prov_sess_response = 
                  new ProvisioningSessionResponseEncoder (sess.getClientEphemeralKey (),
                                                          prov_sess_req.getServerSessionID (),
                                                          sess.getClientSessionID (),
                                                          prov_sess_req.getServerTime (),
                                                          client_time,
                                                          sess.getSessionAttestation (),
                                                          device_info.getDeviceCertificatePath ());
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
        // Get key initialization request and respond with freshly generated public keys
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] KeyInitResponse (byte[] xmldata) throws IOException
          {
            key_init_request = (KeyInitializationRequestDecoder) client_xml_cache.parse (xmldata);
            KeyInitializationResponseEncoder key_init_response = 
                  new KeyInitializationResponseEncoder (key_init_request);
            int pin_policy_handle = 0;
            int puk_policy_handle = 0;
            for (KeyInitializationRequestDecoder.KeyObject key : key_init_request.getKeyObjects ())
              {
                byte[] pin_value = key.getPresetPIN ();
                if (key.getPINPolicy () == null)
                  {
                    pin_policy_handle = key.isDevicePINProtected () ? 0xFFFFFFFF : 0;
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
                            KeyInitializationRequestDecoder.PUKPolicy puk_policy = key.getPINPolicy ().getPUKPolicy ();
                            puk_policy_handle = sks.createPUKPolicy (provisioning_handle, 
                                                                     puk_policy.getID (),
                                                                     puk_policy.getEncryptedValue (),
                                                                     puk_policy.getFormat ().getSKSValue (),
                                                                     puk_policy.getRetryLimit (),
                                                                     puk_policy.getMAC());
                          }
                        KeyInitializationRequestDecoder.PINPolicy pin_policy = key.getPINPolicy ();
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
                KeyPair kpr = sks.createKeyPair (provisioning_handle,
                                                 key.getID (),
                                                 key_init_request.getKeyAttestationAlgorithm (),
                                                 key.getServerSeed (),
                                                 pin_policy_handle,
                                                 pin_value,
                                                 key.getBiometricProtection ().getSKSValue (),
                                                 key.getPrivateKeyBackupFlag (),
                                                 key.getExportPolicy ().getSKSValue (),
                                                 key.getDeletePolicy ().getSKSValue (),
                                                 key.getEnablePINCachingFlag (),
                                                 key.getKeyUsage ().getSKSValue (),
                                                 key.getFriendlyName (),
                                                 key.getKeyAlgorithmData ().getSKSValue (),
                                                 key.getMAC ());
                key_init_response.addPublicKey (kpr.getPublicKey (),
                                                kpr.getKeyAttestation (),
                                                key.getID (),
                                                kpr.getPrivateKey ());
              }
            return key_init_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get the certificates and attributes and return a success message
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDepResponse (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            CredentialDeploymentRequestDecoder cred_dep_request =
                           (CredentialDeploymentRequestDecoder) client_xml_cache.parse (xmldata);
            /* 
               Note: we could have used the saved provisioning_handle but that would not
               work for certifications that are delayed.  The following code is working
               for fully interactive and delayed scenarios by using SKS as state-holder
            */
            EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
            while (true)
              {
                eps = sks.enumerateProvisioningSessions (eps, true);
                if (!eps.isValid ())
                  {
                    abort ("Provisioning session not found:" + 
                        cred_dep_request.getClientSessionID () + "/" +
                        cred_dep_request.getServerSessionID ());
                  }
                if (eps.getClientSessionID ().equals(cred_dep_request.getClientSessionID ()) &&
                    eps.getServerSessionID ().equals (cred_dep_request.getServerSessionID ()))
                  {
                    break;
                  }
              }
            
            //////////////////////////////////////////////////////////////////////////
            // Final check, do these keys match the request?
            //////////////////////////////////////////////////////////////////////////
            for (CredentialDeploymentRequestDecoder.DeployedKeyEntry key : cred_dep_request.getDeployedKeyEntrys ())
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
                                         key.getSymmetricKeyEndorsedAlgorithms (),
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
                for (CredentialDeploymentRequestDecoder.Extension extension : key.getExtensions ())
                  {
                    sks.addExtension (key_handle,
                                      extension.getBaseType (), 
                                      extension.getQualifier (),
                                      extension.getExtensionType (),
                                      extension.getExtensionData (),
                                      extension.getMAC ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be an pp_updateKey or pp_cloneKeyProtection
                //////////////////////////////////////////////////////////////////////////
                CredentialDeploymentRequestDecoder.PostOperation post_operation = key.getPostOperation ();
                if (post_operation != null)
                  {
                    postProvisioning (post_operation, key_handle);
                  }
              }

            //////////////////////////////////////////////////////////////////////////
            // There may be any number of pp_deleteKey
            //////////////////////////////////////////////////////////////////////////
            for (CredentialDeploymentRequestDecoder.PostOperation pp_del : cred_dep_request.getPostProvisioningDeleteKeys ())
              {
                postProvisioning (pp_del, eps.getProvisioningHandle ());
              }

            //////////////////////////////////////////////////////////////////////////
            // Create final and attested message
            //////////////////////////////////////////////////////////////////////////
            CredentialDeploymentResponseEncoder cre_dep_response = 
                      new CredentialDeploymentResponseEncoder (cred_dep_request,
                                                               sks.closeProvisioningSession (eps.getProvisioningHandle (),
                                                                                             cred_dep_request.getCloseSessionMAC ()));
            return cre_dep_response.writeXML ();
          }
      }
    
    class Server
      {
        static final String PLATFORM_URI = "http://issuer.example.com/platform";

        static final String ISSUER_URI = "http://issuer.example.com/provsess";
        
        static final String KEY_INIT_URL = "http://issuer.example.com/keyinit";

        static final String CRE_DEP_URL = "http://issuer.example.com/credep";

        static final String LOGO_URL = "http://issuer.example.com/images/logo.png";
        
        XMLSchemaCache server_xml_cache;
        
        ServerCredentialStore.PINPolicy pin_policy;

        ServerCredentialStore.PUKPolicy puk_policy;
        
        byte[] predef_server_pin = {'3','1','2','5','8','9'};

        PlatformNegotiationRequestEncoder platform_request;

        KeyInitializationRequestEncoder key_init_request;
        
        ProvisioningSessionRequestEncoder prov_sess_request;

        ServerCredentialStore server_credential_store;
        
        PrivateKey gen_private_key;
        
        String server_session_id;

        class SoftHSM implements ServerSessionKeyInterface
          {
            ////////////////////////////////////////////////////////////////////////////////////////
            // Private and secret keys would in a HSM implementation be represented as handles
            ////////////////////////////////////////////////////////////////////////////////////////
            ECPrivateKey server_ec_private_key;
            
            byte[] session_key;
  
            @Override
            public ECPublicKey generateEphemeralKey () throws IOException, GeneralSecurityException
              {
                KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC", "BC");
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
                KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDHC", "BC");
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
                Signature verifier = Signature.getInstance (signature_algorithm.getJCEName (), "BC");
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
                byte[] key = mac (CryptoConstants.CRYPTO_STRING_ENCRYPTION, new byte[0]);
                Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
                crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (data, 0, 16));
                return crypt.doFinal (data, 16, data.length - 16);
              }

            @Override
            public byte[] encrypt (byte[] data) throws IOException, GeneralSecurityException
              {
                byte[] key = mac (CryptoConstants.CRYPTO_STRING_ENCRYPTION, new byte[0]);
                Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
                byte[] iv = new byte[16];
                new SecureRandom ().nextBytes (iv);
                crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
                return ArrayUtil.add (iv, crypt.doFinal (data));
              }
          }
        
        SoftHSM server_sess_key = new SoftHSM ();

        Server () throws Exception
          {
            server_xml_cache = new XMLSchemaCache ();
            server_xml_cache.addWrapper (PlatformNegotiationResponseDecoder.class);
            server_xml_cache.addWrapper (ProvisioningSessionResponseDecoder.class);
            server_xml_cache.addWrapper (KeyInitializationResponseDecoder.class);
            server_xml_cache.addWrapper (CredentialDeploymentResponseDecoder.class);
          }
        
        void verifyPrivateKeyBackup (ServerCredentialStore.KeyProperties key_prop) throws IOException, GeneralSecurityException
          {
            PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (server_sess_key.decrypt (key_prop.getBackupPrivateKey ()));
            boolean rsa = key_prop.getPublicKey () instanceof RSAPublicKey;
            PrivateKey private_key = KeyFactory.getInstance (rsa ? "RSA" : "EC", "BC").generatePrivate (key_spec);
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
            platform_request =  new PlatformNegotiationRequestEncoder (server_session_id,
                                                                       PLATFORM_URI);
            platform_request.addLogotype (LOGO_URL, "image/png", new byte[]{0,5,6,6}, 200, 150);
            if (ask_for_4096)
              {
                platform_request.getBasicCapabilities ().addRSAKeySize ((short)4096).addRSAKeySize ((short)2048);
              }
            return platform_request.writeXML ();
          }

        //////////////////////////////////////////////////////////////////////////////////
        // Create a provisioning session request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] provSessRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            PlatformNegotiationResponseDecoder platform_response = (PlatformNegotiationResponseDecoder) server_xml_cache.parse (xmldata);
            prov_sess_request =  new ProvisioningSessionRequestEncoder (server_sess_key.generateEphemeralKey (),
                                                                        server_session_id,
                                                                        ISSUER_URI,
                                                                        10000,
                                                                        (short)50);
            if (updatable)
              {
                prov_sess_request.setUpdatable (true);
              }
            return prov_sess_request.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create a key init request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] keyInitRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            ////////////////////////////////////////////////////////////////////////////////////
            // Begin with creating the "SessionKey" that holds just about everything
            ////////////////////////////////////////////////////////////////////////////////////
            ProvisioningSessionResponseDecoder prov_sess_response = (ProvisioningSessionResponseDecoder) server_xml_cache.parse (xmldata);
            prov_sess_response.verifyAndGenerateSessionKey (server_sess_key, prov_sess_request);

            ////////////////////////////////////////////////////////////////////////////////////
            // Here we could/should introduce an SKS identity/brand check
            ////////////////////////////////////////////////////////////////////////////////////
            X509Certificate[] certificate_path = prov_sess_response.getDeviceCertificatePath ();

            try
              {
                server_credential_store = new ServerCredentialStore (prov_sess_response, prov_sess_request);
                key_init_request = new KeyInitializationRequestEncoder (KEY_INIT_URL, server_credential_store, server_sess_key);
                key_init_request.writeXML ();
                fail ("Must not allow empty request");
              }
            catch (IOException e)
              {
                
              }
            server_credential_store = new ServerCredentialStore (prov_sess_response, prov_sess_request);
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
                                                                      3,
                                                                      puk_policy);
                if (add_pin_pattern)
                  {
                    pin_policy.addPatternRestriction (PatternRestriction.THREE_IN_A_ROW);
                    pin_policy.addPatternRestriction (PatternRestriction.SEQUENCE);
                  }
                if (pin_group_shared)
                  {
                    pin_policy.setGrouping (PINGrouping.SHARED);
                  }
                if (input_method != null)
                  {
                    pin_policy.setInputMethod (input_method);
                  }
              }
            ServerCredentialStore.KeyAlgorithmData key_alg =  ecc_key ?
                 new ServerCredentialStore.KeyAlgorithmData.EC (ECDomains.P_256) : new ServerCredentialStore.KeyAlgorithmData.RSA (2048);

            ServerCredentialStore.KeyProperties kp = device_pin ?
                server_credential_store.createDevicePINProtectedKey (KeyUsage.AUTHENTICATION, key_alg) :
                  preset_pin ? server_credential_store.createKeyWithPresetPIN (symmetric_key ? KeyUsage.SYMMETRIC_KEY : KeyUsage.AUTHENTICATION,
                                                                               key_alg, pin_policy,
                                                                               server_sess_key.encrypt (predef_server_pin))
                             :
                server_credential_store.createKey (symmetric_key ? KeyUsage.SYMMETRIC_KEY : KeyUsage.AUTHENTICATION,
                                                   key_alg,
                                                   pin_policy);
            if (symmetric_key || encryption_key)
              {
                kp.setEncryptedSymmetricKey (server_sess_key.encrypt (encryption_key ? AES32BITKEY : OTP_SEED),
                                                                      new String[]{encryption_key ?
                                                     SymEncryptionAlgorithms.AES256_CBC.getURI () : MacAlgorithms.HMAC_SHA1.getURI ()});
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
            if (export_policy != null)
              {
                kp.setExportPolicy (export_policy);
              }
            if (delete_policy != null)
              {
                kp.setDeletePolicy (delete_policy);
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
                                           clone_key_protection.server_sess_key);
              }
            if (update_key != null)
              {
                kp.setUpdatedKey (update_key.server_credential_store.getClientSessionID (), 
                                  update_key.server_credential_store.getServerSessionID (),
                                  update_key.server_credential_store.getKeyProperties ().toArray (new ServerCredentialStore.KeyProperties[0])[0].getCertificatePath ()[0],
                                  update_key.server_sess_key);
              }
            if (delete_key != null)
              {
                server_credential_store.addPostProvisioningDeleteKey (delete_key.server_credential_store.getClientSessionID (), 
                                                                      delete_key.server_credential_store.getServerSessionID (),
                                                                      delete_key.server_credential_store.getKeyProperties ().toArray (new ServerCredentialStore.KeyProperties[0])[0].getCertificatePath ()[0],
                                                                      delete_key.server_sess_key);
              }
            key_init_request = new KeyInitializationRequestEncoder (KEY_INIT_URL, server_credential_store, server_sess_key);
            return key_init_request.writeXML ();
          }


        ///////////////////////////////////////////////////////////////////////////////////
        // Get the key init response and respond with certified public keys and attributes
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDepRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            KeyInitializationResponseDecoder key_init_response = (KeyInitializationResponseDecoder) server_xml_cache.parse (xmldata);
            key_init_response.validateAndPopulate (key_init_request, server_sess_key);
            for (ServerCredentialStore.KeyProperties key_prop : server_credential_store.getKeyProperties ())
              {
                if (key_prop.getPrivateKeyBackupFlag ())
                  {
                    verifyPrivateKeyBackup (key_prop);
                  }
                boolean otp = key_prop.getKeyUsage () == KeyUsage.SYMMETRIC_KEY;
                boolean auth = key_prop.getKeyUsage () == KeyUsage.AUTHENTICATION;
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
                    KeyPairGenerator generator = KeyPairGenerator.getInstance (ecc_key ? "EC" :"RSA", "BC");
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
            CredentialDeploymentRequestEncoder credential_deployment_request 
                           = new CredentialDeploymentRequestEncoder (CRE_DEP_URL, 
                                                                     server_credential_store,
                                                                     server_sess_key);

            return credential_deployment_request.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally we get the attestested response
        ///////////////////////////////////////////////////////////////////////////////////
        void creDepResponse (byte[] xmldata) throws IOException
          {
            CredentialDeploymentResponseDecoder cre_dep_response = (CredentialDeploymentResponseDecoder) server_xml_cache.parse (xmldata);
            cre_dep_response.verifyProvisioningResult (server_credential_store, server_sess_key);
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
            xmlschemas.addWrapper (ProvisioningSessionRequestDecoder.class);
            xmlschemas.addWrapper (ProvisioningSessionResponseDecoder.class);
            xmlschemas.addWrapper (KeyInitializationRequestDecoder.class);
            xmlschemas.addWrapper (KeyInitializationResponseDecoder.class);
            xmlschemas.addWrapper (CredentialDeploymentRequestDecoder.class);
            xmlschemas.addWrapper (CredentialDeploymentResponseDecoder.class);
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
            writeOption ("Device PIN", device_pin);
            writeOption ("Preset PIN", preset_pin);
            writeOption ("PIN patterns", add_pin_pattern);
            writeOption ("ECC Key", ecc_key);
            writeOption ("Server Seed", server_seed);
            writeOption ("PropertyBag", property_bag);
            writeOption ("Symmetric Key", symmetric_key);
            writeOption ("Encryption Key", encryption_key);
            writeOption ("Encrypted Extension", encrypted_extension);
            writeOption ("Private Key Backup", private_key_backup);
            writeOption ("Delete Policy", delete_policy != null);
            writeOption ("Export Policy", export_policy != null);
            writeOption ("Private Key Restore", set_private_key);
            writeOption ("CloneKeyProtection", clone_key_protection != null);
            writeOption ("UpdateKey", update_key != null);
            writeOption ("DeleteKey", delete_key != null);
            server = new Server ();
            client = new Client ();
            byte[] xml;
            xml = fileLogger (server.platformRequest ());
            xml = fileLogger (client.platformResponse (xml));
            xml = fileLogger (server.provSessRequest (xml));
            xml = fileLogger (client.provSessResponse (xml));
            xml = fileLogger (server.keyInitRequest (xml));
            xml = fileLogger (client.KeyInitResponse (xml));
            xml = fileLogger (server.creDepRequest (xml));
            xml = fileLogger (client.creDepResponse (xml));
            server.creDepResponse (xml);
            writeString ("\n");
            EnumeratedKey ek = new EnumeratedKey ();
            while ((ek = sks.enumerateKeys (ek)).isValid ())
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
    public void test1 () throws Exception
      {
        ask_for_4096 = true;
        new Doer ().perform ();
      }
    @Test
    public void test2 () throws Exception
      {
        Doer doer = new Doer ();
        image_prefs = true;
        pin_protection = true;
        doer.perform ();
      }
    @Test
    public void test3 () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        add_pin_pattern = true;
        ecc_key = true;
        doer.perform ();
      }
    @Test
    public void test4 () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        private_key_backup = true;
        ecc_key = true;
        server_seed = true;
        doer.perform ();
      }
    @Test
    public void test5 () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        private_key_backup = true;
        doer.perform ();
      }
    @Test
    public void test6 () throws Exception
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
    public void test7 () throws Exception
      {
        Doer doer = new Doer ();
        updatable = true;
        pin_protection = true;
        puk_protection = true;
        input_method = InputMethod.PROGRAMMATIC;
        doer.perform ();
      }
    @Test
    public void test8 () throws Exception
      {
        Doer doer = new Doer ();
        updatable = true;
        pin_protection = true;
        symmetric_key = true;
        property_bag = true;
        doer.perform ();
        ServerCredentialStore.PropertyBag prop_bag = doer.server.server_credential_store.getKeyProperties ().toArray (new ServerCredentialStore.KeyProperties[0])[0].getPropertyBags ()[0];
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek)).isValid ())
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
                sks.setProperty (ek.getKeyHandle (), prop_bag.getType (), props2[w].getName (), props2[w].getValue () + "w2");
                props1 = sks.getExtension (ek.getKeyHandle (), prop_bag.getType ()).getProperties ();
                for (int i = 0; i < props1.length; i++)
                  {
                    assertTrue ("Prop name error", props1[i].getName ().equals (props2[i].getName ()));
                    assertTrue ("Prop value error", (i == w) ^ props1[i].getValue ().equals (props2[i].getValue ()));
                  }
                sks.setProperty (ek.getKeyHandle (), prop_bag.getType (), props2[w].getName (), props2[w].getValue ());
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
    public void test9 () throws Exception
      {
        Doer doer = new Doer ();
        updatable = true;
        pin_protection = true;
        encryption_key = true;
        symmetric_key = true;
        doer.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek)).isValid ())
          {
            if (ek.getProvisioningHandle () == doer.client.provisioning_handle)
              {
                j++;
                byte[] iv = new byte[16];
                new SecureRandom ().nextBytes (iv);
                byte[] enc = sks.symmetricKeyEncrypt (ek.getKeyHandle (), true, iv, SymEncryptionAlgorithms.AES256_CBC.getURI (), USER_DEFINED_PIN, TEST_STRING);
                assertTrue ("Encrypt/decrypt error", ArrayUtil.compare (sks.symmetricKeyEncrypt (ek.getKeyHandle (), false, iv, SymEncryptionAlgorithms.AES256_CBC.getURI (), USER_DEFINED_PIN, enc),
                                                                        TEST_STRING));
              }
          }
        assertTrue ("Missing keys", j == 1);
      }
    @Test
    public void test10 () throws Exception
      {
        Doer doer = new Doer ();
        updatable = true;
        device_pin = true;
        doer.perform ();
      }
    @Test
    public void test11 () throws Exception
      {
        Doer doer = new Doer ();
        updatable = true;
        pin_protection = true;
        preset_pin = true;
        doer.perform ();
      }
    @Test
    public void test12 () throws Exception
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
        clone_key_protection = doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek)).isValid ())
          {
            if (ek.getProvisioningHandle () == doer2.client.provisioning_handle)
              {
                j++;
                KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                byte[] result = sks.signHashedData (ek.getKeyHandle (),
                                                    SignatureAlgorithms.RSA_SHA256.getURI (),
                                                    doer2.server.predef_server_pin,
                                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
                verify.initVerify (ka.getCertificatePath ()[0]);
                verify.update (TEST_STRING);
                assertTrue ("Bad signature", verify.verify (result));
              }
          }
        assertTrue ("Missing keys", j == 2);
      }
    @Test
    public void test13 () throws Exception
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
        while ((ek = sks.enumerateKeys (ek)).isValid ())
          {
            if (ek.getProvisioningHandle () == doer2.client.provisioning_handle)
              {
                j++;
                KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                byte[] result = sks.signHashedData (ek.getKeyHandle (),
                                                    SignatureAlgorithms.RSA_SHA256.getURI (),
                                                    doer2.server.predef_server_pin,
                                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
                verify.initVerify (ka.getCertificatePath ()[0]);
                verify.update (TEST_STRING);
                assertTrue ("Bad signature", verify.verify (result));
              }
          }
        assertTrue ("Missing keys", j == 1);
      }
    @Test
    public void test14 () throws Exception
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
        while ((ek = sks.enumerateKeys (ek)).isValid ())
          {
            if (ek.getProvisioningHandle () == doer1.client.provisioning_handle)
              {
                j++;
              }
          }
        assertTrue ("Missing keys", j == 0);
      }
    @Test
    public void test15 () throws Exception
      {
        Doer doer = new Doer ();
        set_private_key = true;
        pin_protection = true;
        preset_pin = true;
        doer.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek)).isValid ())
          {
            if (ek.getProvisioningHandle () == doer.client.provisioning_handle)
              {
                j++;
                byte[] result = sks.signHashedData (ek.getKeyHandle (),
                                                    SignatureAlgorithms.RSA_SHA256.getURI (),
                                                    doer.server.predef_server_pin,
                                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                Signature sign = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
                sign.initSign (doer.server.gen_private_key);
                sign.update (TEST_STRING);
                assertTrue ("Bad signature", ArrayUtil.compare (sign.sign (), result));
              }
          }
        assertTrue ("Missing keys", j == 1);
      }
    @Test
    public void test16 () throws Exception
      {
        for (ExportPolicy exp_pol : ExportPolicy.values ())
          {
            Doer doer = new Doer ();
            export_policy = exp_pol;
            if (exp_pol == ExportPolicy.PIN || exp_pol == ExportPolicy.PUK)
              {
                pin_protection = true;
              }
            if (exp_pol == ExportPolicy.PUK)
              {
                puk_protection = true;
              }
            ecc_key = true;
            doer.perform ();
          }
      }
    @Test
    public void test17 () throws Exception
      {
        for (DeletePolicy del_pol : DeletePolicy.values ())
          {
            Doer doer = new Doer ();
            if (del_pol == DeletePolicy.PIN || del_pol == DeletePolicy.PUK)
              {
                pin_protection = true;
              }
            if (del_pol == DeletePolicy.PUK)
              {
                puk_protection = true;
              }
            delete_policy = del_pol;
            ecc_key = true;
            doer.perform ();
          }
      }

  }
