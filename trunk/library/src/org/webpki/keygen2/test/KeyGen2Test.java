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

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.AfterClass;
import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.ca.CA;
import org.webpki.ca.CertSpec;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ECDomains;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.keygen2.CredentialDeploymentRequestDecoder;
import org.webpki.keygen2.CredentialDeploymentRequestEncoder;
import org.webpki.keygen2.CredentialDeploymentResponseDecoder;
import org.webpki.keygen2.CredentialDeploymentResponseEncoder;
import org.webpki.keygen2.CryptoConstants;
import org.webpki.keygen2.KeyInitializationResponseDecoder;
import org.webpki.keygen2.KeyInitializationResponseEncoder;
import org.webpki.keygen2.KeyUsage;
import org.webpki.keygen2.KeyInitializationRequestDecoder;
import org.webpki.keygen2.KeyInitializationRequestEncoder;
import org.webpki.keygen2.PassphraseFormats;
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
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;
import org.webpki.xml.XMLObjectWrapper;

public class KeyGen2Test
  {
    static final byte[] KEY_BACKUP_TEST_STRING = new byte[]{'S','u','c','c','e','s','s',' ','o','r',' ','n','t','?'};
    
    boolean pin_protection;
    
    boolean private_key_backup;
    
    boolean ecc_key;
    
    boolean server_seed;
    
    static FileOutputStream fos;
    
    static SecureKeyStore sks;
    
   
    @BeforeClass
    public static void openFile () throws Exception
      {
        String dir = System.getProperty ("test.dir");
        if (dir.length () > 0)
          {
            fos = new FileOutputStream (dir + "/" + KeyGen2Test.class.getCanonicalName () + ".txt");
          }
        Security.addProvider(new BouncyCastleProvider());
        sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.implementation")).newInstance ();
      }

    @AfterClass
    public static void closeFile () throws Exception
      {
        if (fos != null)
          {
            fos.close ();
          }
      }
    
    class Client
      {
        XMLSchemaCache client_xml_cache;
        
        int provisioning_handle;
        
        KeyInitializationRequestDecoder key_init_request;
        
        ProvisioningSessionRequestDecoder prov_sess_req;
        
        Client () throws Exception
          {
            client_xml_cache = new XMLSchemaCache ();
            client_xml_cache.addWrapper (ProvisioningSessionRequestDecoder.class);
            client_xml_cache.addWrapper (KeyInitializationRequestDecoder.class);
            client_xml_cache.addWrapper (CredentialDeploymentRequestDecoder.class);
          }

        private void abort (String message) throws IOException, SKSException
          {
            sks.abortProvisioningSession (provisioning_handle);
            throw new IOException (message);
          }
        
        ///////////////////////////////////////////////////////////////////////////////////
        // Get prov sess request and respond with epheral keys and and attest
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] provSessResponse (byte[] xmldata) throws Exception
          {
            prov_sess_req = (ProvisioningSessionRequestDecoder) client_xml_cache.parse (xmldata);
            Date client_time = new Date ();
            ProvisioningSession sess = 
                  sks.createProvisioningSession (prov_sess_req.getSessionKeyAlgorithm (),
                                                 prov_sess_req.getServerSessionID (),
                                                 prov_sess_req.getServerEphemeralKey (),
                                                 prov_sess_req.getSubmitURL (), /* IssuerURI */
                                                 true, /* Updatable */
                                                 (int)(client_time.getTime () / 1000),
                                                 prov_sess_req.getSessionLifeTime (),
                                                 prov_sess_req.getSessionKeyLimit ());
            provisioning_handle = sess.getProvisioningHandle ();
            
            DeviceInfo dev = sks.getDeviceInfo ();
            ProvisioningSessionResponseEncoder prov_sess_response = 
                  new ProvisioningSessionResponseEncoder (sess.getClientEphemeralKey (),
                                                          prov_sess_req.getServerSessionID (),
                                                          sess.getClientSessionID (),
                                                          prov_sess_req.getServerTime (),
                                                          client_time,
                                                          sess.getSessionAttestation (),
                                                          dev.getDeviceCertificatePath ());
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
        // Get key init request and respond with freshly generated public keys
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] KeyInitResponse (byte[] xmldata) throws Exception
          {
            key_init_request = (KeyInitializationRequestDecoder) client_xml_cache.parse (xmldata);
            KeyInitializationResponseEncoder key_init_response = 
                  new KeyInitializationResponseEncoder (key_init_request);
            for (KeyInitializationRequestDecoder.KeyObject key : key_init_request.getKeyObjects ())
              {
                KeyPair kpr = sks.createKeyPair (provisioning_handle,
                                                       key_init_request.getKeyAttestationAlgorithm (),
                                                       key.getServerSeed (),
                                                       key.getID (),
                                                       0, /* pin_policy_handle */
                                                       "2457".getBytes ("UTF-8"), /* pin_value */
                                                       key.getBiometricProtection (),
                                                       key.getPrivateKeyBackupFlag (),
                                                       key.getExportPolicy (),
                                                       key.getUpdatableFlag (),
                                                       key.getDeletePolicy (),
                                                       key.getEnablePINCachingFlag (),
                                                       key.getImportPrivateKeyFlag (),
                                                       key.getKeyUsage (),
                                                       key.getFriendlyName (),
                                                       key.getKeyAlgorithmData (),
                                                       key.getMAC ());
                key_init_response.addPublicKey (kpr.getPublicKey (),
                                                kpr.getKeyAttestation (),
                                                key.getID (),
                                                kpr.getEncryptedPrivateKey ());
              }
            return key_init_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get the certificates and attributes and return a success message
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDepResponse (byte[] xmldata) throws Exception
          {
            CredentialDeploymentRequestDecoder cred_dep_request =
                           (CredentialDeploymentRequestDecoder) client_xml_cache.parse (xmldata);
            /* 
               Note: we could have saved provisioning_handle but that would not work
               for certifications that are delayed.  The following code is working
               for fully interactive and delayed scenarios by using SKS as state-holder
            */
            provisioning_handle = EnumeratedProvisioningSession.INIT;
            EnumeratedProvisioningSession eps;
            while ((provisioning_handle = (eps = sks.enumerateProvisioningSessions (provisioning_handle, true)).getProvisioningHandle ()) != 0xFFFFFFFF)
              {
                if (eps.getClientSessionID ().equals(cred_dep_request.getClientSessionID ()) &&
                    eps.getServerSessionID ().equals (cred_dep_request.getServerSessionID ()))
                  {
                    break;
                  }
              }
            if (provisioning_handle == EnumeratedProvisioningSession.EXIT)
              {
                abort ("Provisioning session not found:" + 
                        cred_dep_request.getClientSessionID () + "/" +
                        cred_dep_request.getServerSessionID ());
              }
            HashMap<String,Integer> keys = new HashMap<String,Integer> ();
            // Find keys belonging to this provisioning session
            int key_handle = EnumeratedKey.INIT;
            EnumeratedKey ek;
            while ((key_handle = (ek = sks.enumerateKeys (key_handle, true)).getKeyHandle ()) != EnumeratedKey.EXIT)
              {
                if (ek.getProvisioningHandle () == provisioning_handle)
                  {
                    keys.put (ek.getID (), key_handle);
                  }
              }
            // Final check, do these keys match the request?
            for (CredentialDeploymentRequestDecoder.CertifiedPublicKey key : cred_dep_request.getCertifiedPublicKeys ())
              {
                Integer kh = keys.get (key.getID ());
                if (kh == null)
                  {
                    abort ("Did not find key:" + key.getID () + " in deployment request");
                  }
                sks.setCertificatePath (kh, key.getCertificatePath (), key.getMAC ());
              }
            CredentialDeploymentResponseEncoder cre_dep_response = 
                      new CredentialDeploymentResponseEncoder (cred_dep_request,
                                                               sks.closeProvisioningSession (provisioning_handle,
                                                                                             cred_dep_request.getCloseSessionMAC ()));
            return cre_dep_response.writeXML ();
          }
      }
    
    class Server
      {
        static final String ISSUER_URI = "http://issuer.example.com/provsess";
        
        static final String KEY_INIT_URL = "http://issuer.example.com/keyinit";

        static final String CRE_DEP_URL = "http://issuer.example.com/credep";
        
        XMLSchemaCache server_xml_cache;
        
        ServerCredentialStore.PINPolicy pin_policy;

        ServerCredentialStore.PUKPolicy puk_policy;
        
        ServerCredentialStore.KeyAlgorithmData key_alg1 =  new ServerCredentialStore.KeyAlgorithmData.RSA (2048);

        ServerCredentialStore.KeyAlgorithmData key_alg2 =  new ServerCredentialStore.KeyAlgorithmData.EC (ECDomains.P_256);

        KeyInitializationRequestEncoder key_init_request;
        
        ProvisioningSessionRequestEncoder prov_sess_request;

        ServerCredentialStore server_credential_store;

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
                ECGenParameterSpec eccgen = new ECGenParameterSpec ("P-256");
                generator.initialize (eccgen, new SecureRandom ());
                java.security.KeyPair kp = generator.generateKeyPair();
                server_ec_private_key = (ECPrivateKey) kp.getPrivate ();
                return (ECPublicKey) kp.getPublic ();
              }

            @Override
            public void generateAndVerifySessionKey (ECPublicKey client_ephemeral_key,
                                                     byte[] kdf_data,
                                                     byte[] session_key_mac_data,
                                                     PublicKey device_public_key,
                                                     byte[] session_attestation,
                                                     SignatureAlgorithms signature_algorithm) throws IOException, GeneralSecurityException
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
            server_xml_cache.addWrapper (KeyInitializationResponseDecoder.class);
            server_xml_cache.addWrapper (ProvisioningSessionResponseDecoder.class);
            server_xml_cache.addWrapper (CredentialDeploymentResponseDecoder.class);
          }
        
        void verifyPrivateKeyBackup (ServerCredentialStore.KeyProperties key_prop) throws IOException, GeneralSecurityException
          {
            PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (server_sess_key.decrypt (key_prop.getEncryptedPrivateKey ()));
            boolean rsa = key_prop.getPublicKey () instanceof RSAPublicKey;
            PrivateKey private_key = KeyFactory.getInstance (rsa ? "RSA" : "EC").generatePrivate (key_spec);
            Signature sign = Signature.getInstance ((rsa ? SignatureAlgorithms.RSA_SHA256 : SignatureAlgorithms.ECDSA_SHA256).getJCEName ());
            sign.initSign (private_key);
            sign.update (KEY_BACKUP_TEST_STRING);
            byte[] key_archival_verify = sign.sign ();
            Signature verify = Signature.getInstance ((rsa ? SignatureAlgorithms.RSA_SHA256 : SignatureAlgorithms.ECDSA_SHA256).getJCEName ());
            verify.initVerify (key_prop.getPublicKey ());
            verify.update (KEY_BACKUP_TEST_STRING);
            if (!verify.verify (key_archival_verify))
              {
                throw new GeneralSecurityException ("Archived private key validation failed");
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create a prov session req for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] provSessRequest () throws Exception
          {
            prov_sess_request =  new ProvisioningSessionRequestEncoder (server_sess_key.generateEphemeralKey (),
                                                                        "S.7767676dfrgfd",
                                                                        ISSUER_URI,
                                                                        10000,
                                                                        50);
            return prov_sess_request.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create a key init request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] keyInitRequest (byte[] xmldata) throws Exception
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
            if (pin_protection)
              {
                pin_policy = server_credential_store.createPINPolicy (PassphraseFormats.NUMERIC, 4, 8, 3, puk_policy);
              }
            server_credential_store.createKey (KeyUsage.AUTHENTICATION, key_alg1, pin_policy);
            if (ecc_key)
              {
                ServerCredentialStore.KeyProperties kp = server_credential_store.createKey (KeyUsage.ENCRYPTION, key_alg2, pin_policy);
                if (private_key_backup)
                  {
                    kp.setPrivateKeyBackup (true);
                  }
                if (server_seed)
                  {
                    byte[] seed = new byte[32];
                    new SecureRandom ().nextBytes (seed);
                    kp.setServerSeed (seed);
                  }
              }
            key_init_request = new KeyInitializationRequestEncoder (KEY_INIT_URL, server_credential_store, server_sess_key);
            return key_init_request.writeXML ();
          }


        ///////////////////////////////////////////////////////////////////////////////////
        // Get the key init response and respond with certified public keys and attributes
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDepRequest (byte[] xmldata) throws Exception
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
                cert_spec.setSubject ("CN=John Doe, E=john.doe@example.com" +
                                      (otp ? ", OU=OTP Key" : ""));

                GregorianCalendar start = new GregorianCalendar ();
                GregorianCalendar end = (GregorianCalendar) start.clone ();
                end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);

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
                      
                    },
                                          key_prop.getPublicKey ());
                key_prop.setCertificatePath (new X509Certificate[]{certificate});
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
        void creDepResponse (byte[] xmldata) throws Exception
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
                fos.write (data);
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
        
        byte[] fileLogger (byte[] xmldata) throws Exception
          {
            XMLObjectWrapper xo = xmlschemas.parse (xmldata);
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
            return xmldata;
          }

        
        Doer () throws Exception
          {
            xmlschemas.addWrapper (ProvisioningSessionRequestDecoder.class);
            xmlschemas.addWrapper (ProvisioningSessionResponseDecoder.class);
            xmlschemas.addWrapper (KeyInitializationRequestDecoder.class);
            xmlschemas.addWrapper (KeyInitializationResponseDecoder.class);
            xmlschemas.addWrapper (CredentialDeploymentRequestDecoder.class);
            xmlschemas.addWrapper (CredentialDeploymentResponseDecoder.class);
          }
        
        void perform () throws Exception
          {
            writeString ("Begin Test\nPINs = ");
            writeString (pin_protection ? "Yes\n" : "No\n");
            server = new Server ();
            client = new Client ();
            byte[] xml;
            xml = fileLogger (server.provSessRequest ());
            xml = fileLogger (client.provSessResponse (xml));
            xml = fileLogger (server.keyInitRequest (xml));
            xml = fileLogger (client.KeyInitResponse (xml));
            xml = fileLogger (server.creDepRequest (xml));
            xml = fileLogger (client.creDepResponse (xml));
            server.creDepResponse (xml);
            writeString ("\n\n");
            int key_handle = EnumeratedKey.INIT;
            EnumeratedKey ek;
            while ((key_handle = (ek = sks.enumerateKeys (key_handle, false)).getKeyHandle ()) != EnumeratedKey.EXIT)
              {
                if (ek.getProvisioningHandle () == client.provisioning_handle)
                  {
                    KeyAttributes ka = sks.getKeyAttributes (key_handle);
                    writeString ("Deployed key[" + key_handle + "] " + CertificateUtil.convertRFC2253ToLegacy (ka.getCertificatePath ()[0].getSubjectX500Principal ().getName ()) + "\n");
                  }
              }
            writeString ("\n\n");
            
         }
        
      }

    @Test
    public void test1 () throws Exception
      {
        new Doer ().perform ();
      }
    @Test
    public void test2 () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        doer.perform ();
      }
    @Test
    public void test3 () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
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

  }
