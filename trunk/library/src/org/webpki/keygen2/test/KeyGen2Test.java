package org.webpki.keygen2.test;

import java.io.FileOutputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
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
import org.webpki.crypto.test.ECKeys;

import org.webpki.keygen2.AttestationVerifier;
import org.webpki.keygen2.CredentialDeploymentRequestDecoder;
import org.webpki.keygen2.CredentialDeploymentRequestEncoder;
import org.webpki.keygen2.CredentialDeploymentResponseDecoder;
import org.webpki.keygen2.CredentialDeploymentResponseEncoder;
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
import org.webpki.sks.KeyPairResult;
import org.webpki.sks.ProvisioningSessionResult;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;
import org.webpki.sks.SessionKeyOperations;
import org.webpki.util.ArrayUtil;
import org.webpki.xml.XMLSchemaCache;
import org.webpki.xml.XMLObjectWrapper;

public class KeyGen2Test
  {
    boolean pin_protection;
    
    boolean ecc_key;
    
    static FileOutputStream fos;
   
    @BeforeClass
    public static void openFile () throws Exception
      {
        String dir = System.getProperty ("test.dir");
        if (dir.length () > 0)
          {
            fos = new FileOutputStream (dir + "/" + KeyGen2Test.class.getCanonicalName () + ".txt");
          }
        Security.addProvider(new BouncyCastleProvider());
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
        
        SecureKeyStore sks;
        
        int provisioning_handle;
        
        KeyInitializationRequestDecoder key_init_request;
        
        ProvisioningSessionRequestDecoder prov_sess_req;
        
        Client () throws Exception
          {
            sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.implementation")).newInstance ();
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
            ProvisioningSessionResult sess = 
                  sks.createProvisioningSession (prov_sess_req.getSessionKeyAlgorithm (),
                                                 prov_sess_req.getServerSessionID (),
                                                 prov_sess_req.getServerEphemeralKey (),
                                                 prov_sess_req.getSubmitURL (), /* IssuerURI */
                                                 true, /* Updatable */
                                                 client_time,
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
                    return MacAlgorithms.HMAC_SHA256.digest (Constants.SESSION_KEY, data);
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
                KeyPairResult kpr = sks.createKeyPair (provisioning_handle,
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
                                                       key.getKeyAlgorithmData ());
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

        ServerCredentialStore server_credential_store;
        
        class SessionKey implements ServerSessionKeyInterface, SessionKeyOperations
          {
            ECPrivateKey ec_private_key;
            
            byte[] session_key;
  
            @Override
            public ECPublicKey generateEphemeralKey () throws IOException, GeneralSecurityException
              {
                KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC", "BC");
                ECGenParameterSpec eccgen = new ECGenParameterSpec ("P-256");
                generator.initialize (eccgen, new SecureRandom ());
                KeyPair kp = generator.generateKeyPair();
                ec_private_key = (ECPrivateKey) kp.getPrivate ();
                return (ECPublicKey) kp.getPublic ();
              }

            @Override
            public void generateSessionKey (ECPublicKey client_ephemeral_key,
                                            String client_session_id,
                                            String server_session_id,
                                            String issuer_uri) throws IOException, GeneralSecurityException
              {
                byte[] kdf_data = new StringBuffer (client_session_id).append (server_session_id).append (issuer_uri).toString ().getBytes ("UTF-8");
                KeyAgreement ka = KeyAgreement.getInstance ("ECDHC", "BC");
                ka.init (ec_private_key);
                ka.doPhase (client_ephemeral_key, true);
                Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
                mac.init (new SecretKeySpec (ka.generateSecret (), "RAW"));
                session_key = mac.doFinal (kdf_data);
              }

            @Override
            public byte[] getMac (byte[] data, byte[] key_modifier) throws IOException, GeneralSecurityException
              {
                Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
                mac.init (new SecretKeySpec (ArrayUtil.add (session_key, key_modifier), "RAW"));
                return mac.doFinal (data);
              }

            @Override
            public byte[] getAttest (byte[] data) throws IOException, GeneralSecurityException
              {
                return getMac (data, ATTEST_MODIFIER);
              }
          }
        
        SessionKey server_sess_key = new SessionKey ();

        Server () throws Exception
          {
            server_xml_cache = new XMLSchemaCache ();
            server_xml_cache.addWrapper (KeyInitializationResponseDecoder.class);
            server_xml_cache.addWrapper (ProvisioningSessionResponseDecoder.class);
            server_xml_cache.addWrapper (CredentialDeploymentResponseDecoder.class);
         }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create a prov session req for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] provSessRequest () throws Exception
          {
            ProvisioningSessionRequestEncoder prov_sess_req =
                new ProvisioningSessionRequestEncoder (server_sess_key.generateEphemeralKey (),
                                                       Constants.SERVER_SESSION_ID,
                                                       ISSUER_URI,
                                                       10000,
                                                       50);
            return prov_sess_req.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create a key init request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] keyInitRequest (byte[] xmldata) throws Exception
          {
            ProvisioningSessionResponseDecoder prov_sess_response = (ProvisioningSessionResponseDecoder) server_xml_cache.parse (xmldata);
            server_sess_key.generateSessionKey (prov_sess_response.getClientEphemeralKey (),
                                                prov_sess_response.getClientSessionID (),
                                                Constants.SERVER_SESSION_ID,
                                                ISSUER_URI);
            try
              {
                server_credential_store = new ServerCredentialStore (prov_sess_response.getClientSessionID (),
                                                                     Constants.SERVER_SESSION_ID,
                                                                     ISSUER_URI);
                key_init_request = new KeyInitializationRequestEncoder (KEY_INIT_URL, server_credential_store);
                key_init_request.writeXML ();
                fail ("Must not allow empty request");
              }
            catch (IOException e)
              {
                
              }
            server_credential_store = new ServerCredentialStore (prov_sess_response.getClientSessionID (),
                                                                 Constants.SERVER_SESSION_ID,
                                                                 ISSUER_URI);
            if (pin_protection)
              {
                pin_policy = server_credential_store.createPINPolicy (PassphraseFormats.NUMERIC, 4, 8, 3, puk_policy);
              }
            server_credential_store.createKey (KeyUsage.AUTHENTICATION, key_alg1, pin_policy);
            if (ecc_key)
              {
                server_credential_store.createKey (KeyUsage.ENCRYPTION, key_alg2, pin_policy);
              }
            key_init_request = new KeyInitializationRequestEncoder (KEY_INIT_URL, server_credential_store);
            return key_init_request.writeXML ();
          }


        ///////////////////////////////////////////////////////////////////////////////////
        // Get the key init response and respond with certified public keys and attributes
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDepRequest (byte[] xmldata) throws Exception
          {
            KeyInitializationResponseDecoder key_init_response = (KeyInitializationResponseDecoder) server_xml_cache.parse (xmldata);
            key_init_response.validateAndPopulate (key_init_request,
                                                   new AttestationVerifier ()
              {

                @Override
                public void verifyAttestation (byte[] attestation, byte[] data) throws IOException
                  {
                    // TODO Auto-generated method stub
                    
                  }
                
              });
            for (ServerCredentialStore.KeyProperties key_prop : server_credential_store.getKeyProperties ())
              {
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
            while ((key_handle = (ek = client.sks.enumerateKeys (key_handle, false)).getKeyHandle ()) != EnumeratedKey.EXIT)
              {
                if (ek.getProvisioningHandle () == client.provisioning_handle)
                  {
                    KeyAttributes ka = client.sks.getKeyAttributes (key_handle);
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

  }
