/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Vector;

import javax.crypto.KeyAgreement;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
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
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.keygen2.Action;
import org.webpki.keygen2.BasicCapabilities;
import org.webpki.keygen2.KeyGen2Constants;
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
import org.webpki.keygen2.ServerState;

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
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.Property;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.sks.ws.WSSpecific;

import org.webpki.tools.XML2HTMLPrinter;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HTMLHeader;
import org.webpki.util.ImageData;

import org.webpki.xml.XMLSchemaCache;
import org.webpki.xml.XMLObjectWrapper;

/*
 * KeyGen2 "Protocol Exerciser" / JUnit Test
 */
public class KeyGen2Test
  {
    static final byte[] TEST_STRING = {'S','u','c','c','e','s','s',' ','o','r',' ','n','o','t','?'};

    boolean pin_protection;
    
    boolean ecc_key;
    
    boolean two_keys;
    
    boolean key_agreement;
    
    boolean server_seed;
    
    boolean property_bag;
    
    boolean symmetric_key;
    
    boolean updatable;
    
    boolean ecc_kmk;
    
    boolean fixed_pin;
    
    Server clone_key_protection;
    
    Server update_key;
    
    Server delete_key;
    
    Server plain_unlock_key;
    
    boolean device_pin_protection;
    
    boolean enable_pin_caching;
    
    boolean privacy_enabled;
    
    boolean pin_group_shared;
    
    boolean puk_protection;
    
    boolean add_pin_pattern;
    
    boolean preset_pin;
    
    boolean encryption_key;
    
    boolean set_private_key;
    
    boolean set_logotype;
    
    boolean encrypted_extension;
    
    boolean set_trust_anchor;
    
    boolean virtual_machine;
    
    boolean get_client_attributes;
    
    boolean https;  // Use server-cert
    
    boolean ask_for_4096;
    
    boolean ask_for_exponent;
    
    boolean set_abort_url;
    
    ExportProtection export_protection;
    
    DeleteProtection delete_protection;
    
    InputMethod input_method;
    
    boolean image_prefs;
    
    static FileOutputStream fos;
    
    static SecureKeyStore sks;
    
    static final byte[] OTP_SEED = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    
    static final byte[] AES32BITKEY = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    
    static final byte[] USER_DEFINED_PIN = {'0','1','5','3','5','4'};

    static final byte[] PREDEF_SERVER_PIN = {'3','1','2','5','8','9'};
    
    static final byte[] BAD_PIN = {0x03, 0x33, 0x03, 0x04};

    static final String ABORT_URL = "http://issuer.example.com/abort";

    static final String PLATFORM_URL = "http://issuer.example.com/platform";

    static final String ISSUER_URL = "http://issuer.example.com/provsess";
    
    static final String KEY_INIT_URL = "http://issuer.example.com/keyinit";

    static final String FIN_PROV_URL = "http://issuer.example.com/finalize";

    static final String CRE_DISC_URL = "http://issuer.example.com/credisc";
    
    static final String ACME_INDUSTRIES = "Acme Industries";
    
    static X509Certificate server_certificate;
    
    int round;
   
    @BeforeClass
    public static void openFile () throws Exception
      {
        String dir = System.getProperty ("test.dir");
        if (dir.length () > 0)
          {
            fos = new FileOutputStream (dir + "/keygen2.junit.run.html");
            fos.write (HTMLHeader.createHTMLHeader (false, true,"KeyGen2 JUinit test output", null).append ("<body><h3>KeyGen2 JUnit Test</h3><p>").toString ().getBytes ("UTF-8"));
          }
        Security.insertProviderAt (new BouncyCastleProvider(), 1);
        server_certificate = (X509Certificate) CertificateFactory.getInstance ("X.509").generateCertificate (KeyGen2Test.class.getResourceAsStream ("server-certificate.der"));
        sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.implementation")).newInstance ();
        if (fos != null)
          {
            DeviceInfo dev = sks.getDeviceInfo ();
            fos.write (("<b>SKS Description: " + dev.getVendorDescription () +
                        "<br>SKS Vendor: " + dev.getVendorName () +
                        "<br>SKS API Level: " + dev.getAPILevel () +
                        "<br>SKS Interface: " + (sks instanceof WSSpecific ? "WebService" : "Direct") +
                        "<br>&nbsp<br></b>").getBytes ("UTF-8"));
          }
        if (sks instanceof WSSpecific)
          {
            String device_id = System.getProperty ("sks.device");
            if (device_id != null && device_id.length () != 0)
              {
                ((WSSpecific) sks).setDeviceID (device_id);
              }
          }
      }

    @AfterClass
    public static void closeFile () throws Exception
      {
        if (fos != null)
          {
            fos.write ("</body></html>".getBytes ("UTF-8"));
            fos.close ();
          }
      }
    
    @Before
    public void setup () throws Exception
      {
         if (sks instanceof WSSpecific)
           {
             ((WSSpecific)sks).logEvent ("Testing:" + _name.getMethodName ());
           }
      }
        
    @After
    public void teardown () throws Exception
      {
      }
    @Rule 
    public TestName _name = new TestName();
    
    static class KeyCreator
      {
        private static final String kg2keycre = 
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
          "<KeyCreationRequest Algorithm=\"http://xmlns.webpki.org/keygen2/1.0#algorithm.sks.k1\" " +
          "ClientSessionID=\"C-139622a0ac98f2f44a35c9753ca\" " +
          "ID=\"S-139622a0a9993085d38d1586b76\" " +
          "SubmitURL=\"http://issuer.example.com/keyinit\" " +
          "xmlns=\"" + KeyGen2Constants.KEYGEN2_NS + "\">";
      
        private static XMLSchemaCache xml_cache;
        
        static
        {
          try
            {
              xml_cache = new XMLSchemaCache ();
              xml_cache.addWrapper (KeyCreationRequestDecoder.class);
            }
          catch (IOException e)
            {
            }
        }
        
        private StringBuffer xml = new StringBuffer (kg2keycre);
        
        private int key_id;
        
        private int pin_id;
        
        private boolean pin_active;
        
        KeyCreator () throws IOException
          {
          }
        
        KeyCreator addPIN (PassphraseFormat format, Grouping grouping, PatternRestriction[] patterns)
          {
            finishPIN ();
            pin_active = true;
            if (grouping == null)
              {
                grouping = Grouping.NONE;
              }
            xml.append ("<PINPolicy Format=\"")
               .append (format.getXMLName ())
               .append ("\" ID=\"PIN.")
               .append (++pin_id)
               .append ("\" Grouping=\"")
               .append (grouping.getXMLName ())
               .append ("\"");
            if (patterns != null)
              {
                xml.append (" PatternRestrictions=\"");
                String blank="";
                for (PatternRestriction pattern : patterns)
                  {
                    xml.append (blank);
                    blank = " ";
                    xml.append (pattern.getXMLName ());
                  }
                xml.append ("\"");
              }
            xml.append (" MAC=\"3dGegeDJ1enpEzCgwdbXJirNZ95wooM6ordOGW/AJ+0=\" MaxLength=\"8\" MinLength=\"4\" RetryLimit=\"3\">");
            return this;
          }
        
        private void finishPIN ()
          {
            if (pin_active)
              {
                pin_active = false;
                xml.append ("</PINPolicy>");
              }
          }

        KeyCreator addKey (AppUsage app_usage)
          {
            xml.append ("<KeyEntry AppUsage=\"")
               .append (app_usage.getXMLName ())
               .append ("\" ID=\"Key.")
               .append (++key_id)
               .append ("\" KeyAlgorithm=\"http://xmlns.webpki.org/keygen2/1.0#algorithm.rsa2048\" MAC=\"Jrqigi79Yw6SoLobsBA5S8b74gTKrIJPh3tQRKci33Y=\"/>");
            return this;
          }

        KeyCreationRequestDecoder parse () throws Exception
          {
            finishPIN ();
            return (KeyCreationRequestDecoder)xml_cache.parse (xml.append ("</KeyCreationRequest>").toString ().getBytes ("UTF-8"));
          }
      }

    boolean PINCheck (PassphraseFormat format, PatternRestriction[] patterns, String pin) throws Exception
      {
        KeyCreator kc = new KeyCreator ();
        kc.addPIN (format, null, patterns);
        kc.addKey (AppUsage.AUTHENTICATION);
        KeyCreationRequestDecoder.UserPINDescriptor upd = kc.parse ().getUserPINDescriptors ().elementAt (0);
        KeyCreationRequestDecoder.UserPINError pin_test = upd.setPIN (pin, false);
        KeyCreationRequestDecoder.UserPINError pin_set = upd.setPIN (pin, true);
        if ((pin_test == null) ^ (pin_set == null))
          {
            throw new IOException ("PIN test/set confusion");
          }
        return pin_set == null;
      }
    
    void PINGroupCheck (Grouping grouping, AppUsage[] keys, String[] pins, int[] index, boolean fail) throws Exception
      {
        KeyCreator kc = new KeyCreator ();
        kc.addPIN (PassphraseFormat.NUMERIC, grouping, null);
        for (AppUsage app_usage : keys)
          {
            kc.addKey (app_usage);
          }
        KeyCreationRequestDecoder decoder = kc.parse ();
        String error = null;
        if (decoder.getUserPINDescriptors ().size () != pins.length)
          {
            error = "Wrong number of PINs";
          }
        else
          {
            int i = 0;
            for (KeyCreationRequestDecoder.UserPINDescriptor upd : decoder.getUserPINDescriptors ())
              {
                if (upd.setPIN (pins[i++], true) != null)
                  {
                    error = "PIN return error";
                    break;
                  }
              }
            if (error == null)
              {
                i = 0;
                for (KeyCreationRequestDecoder.KeyObject ko : decoder.getKeyObjects ())
                  {
                    if (!ArrayUtil.compare (ko.getSKSPINValue (), pins[index[i++]].getBytes ("UTF-8")))
                      {
                        error = "Grouping problem";
                        break;
                      }
                  }
              }
          }
        if (error == null)
          {
            if (fail) throw new IOException ("Error expected");
          }
        else if (!fail)
          {
            throw new IOException ("Unexpected error: " + error);
          }
      }

    class Client
      {
        XMLSchemaCache client_xml_cache;
        
        int provisioning_handle;
        
        KeyCreationRequestDecoder key_creation_request;
        
        ProvisioningInitializationRequestDecoder prov_sess_req;
        
        PlatformNegotiationRequestDecoder platform_req;

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
                              sks.postCloneKeyProtection (handle, ek.getKeyHandle (), post_operation.getAuthorization (), post_operation.getMAC ());
                              break;

                            case ProvisioningFinalizationRequestDecoder.PostOperation.UPDATE_KEY:
                              sks.postUpdateKey (handle, ek.getKeyHandle (),  post_operation.getAuthorization (), post_operation.getMAC ());
                              break;

                            case ProvisioningFinalizationRequestDecoder.PostOperation.UNLOCK_KEY:
                              sks.postUnlockKey (handle, ek.getKeyHandle (),  post_operation.getAuthorization (), post_operation.getMAC ());
                              break;

                            default:
                              sks.postDeleteKey (handle, ek.getKeyHandle (), post_operation.getAuthorization (), post_operation.getMAC ());
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
            platform_req = (PlatformNegotiationRequestDecoder) client_xml_cache.parse (xmldata);
            if (set_abort_url)
              {
                assertTrue ("Abort URL", platform_req.getAbortURL ().equals (ABORT_URL));
              }
            else
              {
                assertTrue ("Abort URL", platform_req.getAbortURL () == null);
              }
            device_info = sks.getDeviceInfo ();
            PlatformNegotiationResponseEncoder platform_response = new PlatformNegotiationResponseEncoder (platform_req);
            BasicCapabilities basic_capabilties_response = platform_response.getBasicCapabilities ();
            BasicCapabilities basic_capabilties_request = platform_req.getBasicCapabilities ();
            Vector<String> matches = new Vector<String> ();
            for (String want : basic_capabilties_request.getAlgorithms ())
              {
                for (String have : device_info.getSupportedAlgorithms ())
                  {
                    if (have.equals (want))
                      {
                        matches.add (have);
                        break;
                      }
                  }
              }
            for (String algorithm : matches)
              {
                basic_capabilties_response.addAlgorithm (algorithm);
              }
            for (String client_attribute : basic_capabilties_request.getClientAttributes ())
              {
                if (client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER) || client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IP_ADDRESS))
                  {
                    basic_capabilties_response.addClientAttribute (client_attribute);
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
            assertTrue ("Submit URL", prov_sess_req.getSubmitURL ().equals (ISSUER_URL));
            assertFalse ("VM", virtual_machine ^ ACME_INDUSTRIES.equals (prov_sess_req.getVirtualMachineFriendlyName ()));
            Date client_time = new Date ();
            ProvisioningSession sess = 
                  sks.createProvisioningSession (prov_sess_req.getSessionKeyAlgorithm (),
                                                 platform_req.getPrivacyEnabledFlag(),
                                                 prov_sess_req.getServerSessionID (),
                                                 prov_sess_req.getServerEphemeralKey (),
                                                 prov_sess_req.getSubmitURL (), /* IssuerURI */
                                                 prov_sess_req.getKeyManagementKey (),
                                                 (int)(client_time.getTime () / 1000),
                                                 prov_sess_req.getSessionLifeTime (),
                                                 prov_sess_req.getSessionKeyLimit ());
            provisioning_handle = sess.getProvisioningHandle ();
            
            ProvisioningInitializationResponseEncoder prov_init_response = 
                  new ProvisioningInitializationResponseEncoder (sess.getClientEphemeralKey (),
                                                                 prov_sess_req.getServerSessionID (),
                                                                 sess.getClientSessionID (),
                                                                 prov_sess_req.getServerTime (),
                                                                 client_time,
                                                                 sess.getAttestation (),
                                                                 platform_req.getPrivacyEnabledFlag () ? null : device_info.getCertificatePath ());
            if (https)
              {
                prov_init_response.setServerCertificate (server_certificate);
              }

            for (String client_attribute : prov_sess_req.getClientAttributes ())
              {
                if (client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER))
                  {
                    prov_init_response.setClientAttributeValue (client_attribute, "490154203237518");
                  }
                else if (client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IP_ADDRESS))
                  {
                    prov_init_response.setClientAttributeValue (client_attribute, "fe80::4465:62dc:5fa5:4766%10")
                                      .setClientAttributeValue (client_attribute, "192.168.0.202");
                  }
              }

            prov_init_response.signRequest (new SymKeySignerInterface ()
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
            return prov_init_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get credential doscovery request
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDiscResponse (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            cre_disc_req = (CredentialDiscoveryRequestDecoder) client_xml_cache.parse (xmldata);
            assertTrue ("Submit URL", cre_disc_req.getSubmitURL ().equals (CRE_DISC_URL));
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
                                cf.setIssuerRegEx (ls.getIssuerRegEx ());
                                cf.setSubjectRegEx (ls.getSubjectRegEx ());
                                cf.setSerial (ls.getSerial ());
                                cf.setEmailAddress (ls.getEmailAddress ());
                                cf.setPolicy (ls.getPolicy ());
                                if (!cf.matches (cert_path, null, null))
                                  {
                                    continue;
                                  }
                                lr.addMatchingCredential (cert_path[0],
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
        byte[] keyCreResponse (byte[] xmldata) throws IOException
          {
            key_creation_request = (KeyCreationRequestDecoder) client_xml_cache.parse (xmldata);
            assertTrue ("Submit URL", key_creation_request.getSubmitURL ().equals (KEY_INIT_URL));
            KeyCreationResponseEncoder key_creation_response = new KeyCreationResponseEncoder (key_creation_request);
            for (KeyCreationRequestDecoder.UserPINDescriptor upd : key_creation_request.getUserPINDescriptors ())
              {
                upd.setPIN (new String (USER_DEFINED_PIN, "UTF-8"), true);
              }
            int pin_policy_handle = 0;
            int puk_policy_handle = 0;
            for (KeyCreationRequestDecoder.KeyObject key : key_creation_request.getKeyObjects ())
              {
                if (key.getPINPolicy () == null)
                  {
                    pin_policy_handle = 0;
                    puk_policy_handle = 0;
                  }
                else
                  {
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
                                                       key_creation_request.getAlgorithm (),
                                                       key.getServerSeed (),
                                                       key.isDevicePINProtected (),
                                                       pin_policy_handle,
                                                       key.getSKSPINValue (),
                                                       key.getEnablePINCachingFlag (),
                                                       key.getBiometricProtection ().getSKSValue (),
                                                       key.getExportProtection ().getSKSValue (),
                                                       key.getDeleteProtection ().getSKSValue (),
                                                       key.getAppUsage ().getSKSValue (),
                                                       key.getFriendlyName (),
                                                       key.getKeySpecifier ().getKeyAlgorithm ().getURI (),
                                                       key.getKeySpecifier ().getParameters (),
                                                       key.getEndorsedAlgorithms (),
                                                       key.getMAC ());
                key_creation_response.addPublicKey (key_data.getPublicKey (),
                                                    key_data.getAttestation (),
                                                    key.getID ());
              }
            return key_creation_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get the certificates and attributes and return a success message
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creFinalizeResponse (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            ProvisioningFinalizationRequestDecoder prov_final_request =
                           (ProvisioningFinalizationRequestDecoder) client_xml_cache.parse (xmldata);
            assertTrue ("Submit URL", prov_final_request.getSubmitURL ().equals (FIN_PROV_URL));
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
                           prov_final_request.getClientSessionID () + "/" +
                           prov_final_request.getServerSessionID ());
                  }
                if (eps.getClientSessionID ().equals(prov_final_request.getClientSessionID ()) &&
                    eps.getServerSessionID ().equals (prov_final_request.getServerSessionID ()))
                  {
                    break;
                  }
              }
            
            //////////////////////////////////////////////////////////////////////////
            // Final check, do these keys match the request?
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.DeployedKeyEntry key : prov_final_request.getDeployedKeyEntrys ())
              {
                int key_handle = sks.getKeyHandle (eps.getProvisioningHandle (), key.getID ());
                sks.setCertificatePath (key_handle, key.getCertificatePath (), key.getMAC ());

                //////////////////////////////////////////////////////////////////////////
                // There may be a symmetric key
                //////////////////////////////////////////////////////////////////////////
                if (key.getEncryptedSymmetricKey () != null)
                  {
                    sks.importSymmetricKey (key_handle, 
                                            key.getEncryptedSymmetricKey (),
                                            key.getSymmetricKeyMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be a private key
                //////////////////////////////////////////////////////////////////////////
                if (key.getEncryptedPrivateKey () != null)
                  {
                    sks.importPrivateKey (key_handle, 
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
                // There may be an postUpdateKey or postCloneKeyProtection
                //////////////////////////////////////////////////////////////////////////
                ProvisioningFinalizationRequestDecoder.PostOperation post_operation = key.getPostOperation ();
                if (post_operation != null)
                  {
                    postProvisioning (post_operation, key_handle);
                  }
              }

            //////////////////////////////////////////////////////////////////////////
            // There may be any number of postUnlockKey
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.PostOperation post_unl : prov_final_request.getPostUnlockKeys ())
              {
                postProvisioning (post_unl, eps.getProvisioningHandle ());
              }

            //////////////////////////////////////////////////////////////////////////
            // There may be any number of postDeleteKey
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.PostOperation post_del : prov_final_request.getPostDeleteKeys ())
              {
                postProvisioning (post_del, eps.getProvisioningHandle ());
              }

            //////////////////////////////////////////////////////////////////////////
            // Create final and attested message
            //////////////////////////////////////////////////////////////////////////
            ProvisioningFinalizationResponseEncoder fin_prov_response = 
                new ProvisioningFinalizationResponseEncoder (prov_final_request,
                                                             sks.closeProvisioningSession (eps.getProvisioningHandle (),
                                                                                           prov_final_request.getCloseSessionNonce (),
                                                                                           prov_final_request.getCloseSessionMAC ()));
            return fin_prov_response.writeXML ();
          }
      }
    
    class Server
      {
        static final String LOGO_URL = "http://issuer.example.com/images/logo.png";
        static final String LOGO_MIME = "image/png";
        byte[] LOGO_SHA256 = {0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6}; 
        static final int LOGO_WIDTH = 200;
        static final int LOGO_HEIGHT = 150;
        
        XMLSchemaCache server_xml_cache;
        
        int pin_retry_limit = 3;

        ServerState server_state;
        
        PrivateKey gen_private_key;
        
        PublicKey server_km;
        
        SoftHSM server_crypto_interface = new SoftHSM ();

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
            // Begin by creating the "SessionKey" that holds the key to just about everything
            ////////////////////////////////////////////////////////////////////////////////////
            ProvisioningInitializationResponseDecoder prov_init_response = (ProvisioningInitializationResponseDecoder) xml_object;

            ////////////////////////////////////////////////////////////////////////////////////
            // Update the container state.  This is where the action is
            ////////////////////////////////////////////////////////////////////////////////////
            server_state.update (prov_init_response, https ? server_certificate : null);

            ////////////////////////////////////////////////////////////////////////////////////
            // Here we could/should introduce an SKS identity/brand check
            ////////////////////////////////////////////////////////////////////////////////////
            X509Certificate[] certificate_path = prov_init_response.getDeviceCertificatePath ();
          }
        
        //////////////////////////////////////////////////////////////////////////////////
        // Create platform negotiation request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] platformRequest () throws IOException, GeneralSecurityException
          {
            ////////////////////////////////////////////////////////////////////////////////////
            // Create the state container
            ////////////////////////////////////////////////////////////////////////////////////
            server_state = new ServerState (server_crypto_interface);

            ////////////////////////////////////////////////////////////////////////////////////
            // First keygen2 request
            ////////////////////////////////////////////////////////////////////////////////////
            String server_session_id = "S-" + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());
            PlatformNegotiationRequestEncoder platform_request =  new PlatformNegotiationRequestEncoder (server_state, PLATFORM_URL, server_session_id);
            if (set_abort_url)
              {
                platform_request.setAbortURL (ABORT_URL);
              }
            BasicCapabilities basic_capabilities = platform_request.getBasicCapabilities ();
            if (ask_for_4096)
              {
                basic_capabilities.addAlgorithm (KeyAlgorithms.RSA4096.getURI ())
                                  .addAlgorithm (KeyAlgorithms.RSA2048.getURI ());
              }
            if (ask_for_exponent)
              {
                basic_capabilities.addAlgorithm (KeyAlgorithms.RSA2048_EXP.getURI ());
              }
            if (get_client_attributes)
              {
                basic_capabilities.addClientAttribute (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER)
                                  .addClientAttribute (KeyGen2URIs.CLIENT_ATTRIBUTES.IP_ADDRESS)
                                  .addClientAttribute (KeyGen2URIs.CLIENT_ATTRIBUTES.MAC_ADDRESS);
              }
            if (plain_unlock_key != null)
              {
                platform_request.setAction (Action.UNLOCK);
              }
            if (privacy_enabled)
              {
                platform_request.setPrivacyEnabled (true);
              }
            return platform_request.writeXML ();
          }

        //////////////////////////////////////////////////////////////////////////////////
        // Create a provisioning session request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] provSessRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            PlatformNegotiationResponseDecoder platform_response = (PlatformNegotiationResponseDecoder) server_xml_cache.parse (xmldata);
            server_state.update (platform_response);
            BasicCapabilities basic_capabilties = platform_response.getBasicCapabilities ();
            if (ask_for_exponent)
              {
                ask_for_exponent = false;
                for (String algorithm : basic_capabilties.getAlgorithms ())
                  {
                    if (algorithm.equals (KeyAlgorithms.RSA2048_EXP.getURI ()))
                      {
                        ask_for_exponent = true;
                      }
                  }
              }
            if (ask_for_4096)
              {
                ask_for_4096 = false;
                for (String algorithm : basic_capabilties.getAlgorithms ())
                  {
                    if (algorithm.equals (KeyAlgorithms.RSA4096.getURI ()))
                      {
                        ask_for_4096 = true;
                      }
                  }
              }

            ProvisioningInitializationRequestEncoder prov_init_request = 
                 new ProvisioningInitializationRequestEncoder (server_state, ISSUER_URL, 10000, (short)50);
            if (updatable || virtual_machine)
              {
                prov_init_request.setKeyManagementKey (server_km = server_crypto_interface.enumerateKeyManagementKeys ()[ecc_kmk ? 2 : 0]);
                if (virtual_machine)
                  {
                    prov_init_request.setVirtualMachineFriendlyName (ACME_INDUSTRIES);
                  }
              }
            return prov_init_request.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create credential discover request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDiscRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            getProvSess (server_xml_cache.parse (xmldata));
            CredentialDiscoveryRequestEncoder cdre = new CredentialDiscoveryRequestEncoder (server_state, CRE_DISC_URL);
            cdre.addLookupDescriptor (server_crypto_interface.enumerateKeyManagementKeys ()[0]);

            cdre.addLookupDescriptor (server_crypto_interface.enumerateKeyManagementKeys ()[2])
                          .setEmailAddress ("john.doe@example.com");

            cdre.addLookupDescriptor (server_crypto_interface.enumerateKeyManagementKeys ()[2])
                          .setEmailAddress ("jane.doe@example.com");

            cdre.addLookupDescriptor (server_crypto_interface.enumerateKeyManagementKeys ()[1])
                          .setEmailAddress ("john.doe@example.com")
                          .setExcludedPolicies (new String[]{"1.3.4","34.90"})
                          .setPolicy ("5.4.8")
                          .setSerial (new BigInteger ("123"))
                          .setIssuedBefore (new Date (new Date ().getTime () - 100000))
                          .setIssuedAfter (new Date ())
                          .setSubjectRegEx ("CN=John")
                          .setIssuerRegEx ("CN=Root CA");
            return cdre.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create a key creation request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] keyCreRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            XMLObjectWrapper xml_object = server_xml_cache.parse (xmldata);
            if (xml_object instanceof ProvisioningInitializationResponseDecoder)
              {
                getProvSess (xml_object);
              }
            else
              {
                CredentialDiscoveryResponseDecoder cdrd = (CredentialDiscoveryResponseDecoder) xml_object;
                server_state.update (cdrd);
                CredentialDiscoveryResponseDecoder.LookupResult[] lres = cdrd.getLookupResults ();
// TODO verify
              }

            ServerState.PINPolicy pin_policy = null;

            ServerState.PUKPolicy puk_policy = null;
            
            if (puk_protection)
              {
                puk_policy =
                    server_state.createPUKPolicy (server_crypto_interface.encrypt (new byte[]{'0','1','2','3','4','5','6', '7','8','9'}),
                                                                                   PassphraseFormat.NUMERIC,
                                                                                   3);
              }
            if (pin_protection)
              {
                pin_policy = server_state.createPINPolicy (PassphraseFormat.NUMERIC,
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
                if (fixed_pin)
                  {
                    pin_policy.setUserModifiable (false);
                  }
              }
            KeySpecifier key_alg = null;
            if (ecc_key)
              {
                key_alg = new KeySpecifier (KeyAlgorithms.P_256);
              }
            else if (ask_for_exponent)
              {
                key_alg = new KeySpecifier (KeyAlgorithms.RSA2048_EXP, 3);
              }
            else
              {
                key_alg = new KeySpecifier (ask_for_4096 ? KeyAlgorithms.RSA4096 : KeyAlgorithms.RSA2048);
              }

            ServerState.Key kp = device_pin_protection ?
                server_state.createDevicePINProtectedKey (AppUsage.AUTHENTICATION, key_alg) :
                  preset_pin ? server_state.createKeyWithPresetPIN (encryption_key ? AppUsage.ENCRYPTION : AppUsage.AUTHENTICATION,
                                                                               key_alg, pin_policy,
                                                                               server_crypto_interface.encrypt (PREDEF_SERVER_PIN))
                             :
            server_state.createKey (encryption_key || key_agreement? AppUsage.ENCRYPTION : AppUsage.AUTHENTICATION,
                                               key_alg,
                                               pin_policy);
            if (symmetric_key || encryption_key)
              {
                kp.setEndorsedAlgorithms (new String[]{encryption_key ? SymEncryptionAlgorithms.AES256_CBC.getURI () : MacAlgorithms.HMAC_SHA1.getURI ()});
                kp.setEncryptedSymmetricKey (server_crypto_interface.encrypt (encryption_key ? AES32BITKEY : OTP_SEED));
              }
            if (key_agreement)
              {
                kp.setEndorsedAlgorithms (new String[]{KeyGen2URIs.SPECIAL_ALGORITHMS.ECDH_RAW});
              }
            if (property_bag)
              {
                kp.addPropertyBag ("http://host/prop")
                  .addProperty ("main", "234", false)
                  .addProperty ("a", "fun", true);
              }
            if (encrypted_extension)
              {
                kp.addEncryptedExtension ("http://host/ee", server_crypto_interface.encrypt (new byte[]{0,5}));
              }
            if (set_logotype)
              {
                kp.addLogotype (KeyGen2URIs.LOGOTYPES.CARD, new ImageData (new byte[]{8,6,4,4}, "image/png"));
              }
            if (export_protection != null)
              {
                kp.setExportProtection (export_protection);
              }
            if (delete_protection != null)
              {
                kp.setDeleteProtection (delete_protection);
              }
            if (enable_pin_caching)
              {
                kp.setEnablePINCaching (true);
              }
            if (server_seed)
              {
                byte[] seed = new byte[32];
                new SecureRandom ().nextBytes (seed);
                kp.setServerSeed (seed);
              }
            if (clone_key_protection != null)
              {
                kp.setClonedKeyProtection (clone_key_protection.server_state.getClientSessionID (), 
                                           clone_key_protection.server_state.getServerSessionID (),
                                           clone_key_protection.server_state.getKeys ()[0].getCertificatePath ()[0],
                                           clone_key_protection.server_km);
              }
            if (update_key != null)
              {
                kp.setUpdatedKey (update_key.server_state.getClientSessionID (), 
                                  update_key.server_state.getServerSessionID (),
                                  update_key.server_state.getKeys ()[0].getCertificatePath ()[0],
                                  update_key.server_km);
              }
            if (delete_key != null)
              {
                server_state.addPostDeleteKey (delete_key.server_state.getClientSessionID (), 
                                               delete_key.server_state.getServerSessionID (),
                                               delete_key.server_state.getKeys ()[0].getCertificatePath ()[0],
                                               delete_key.server_km);
              }
            if (two_keys)
              {
                server_state.createKey (AppUsage.SIGNATURE, new KeySpecifier (KeyAlgorithms.P_256), pin_policy);
              }

            return new KeyCreationRequestEncoder (server_state, KEY_INIT_URL).writeXML ();
          }


        ///////////////////////////////////////////////////////////////////////////////////
        // Get the key create response and respond with certified public keys and attributes
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creFinalizeRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            if (plain_unlock_key == null)
              {
                boolean temp_set_private_key = set_private_key;
                boolean otp = symmetric_key && !encryption_key;
                KeyCreationResponseDecoder key_init_response = (KeyCreationResponseDecoder) server_xml_cache.parse (xmldata);
                server_state.update (key_init_response);
                for (ServerState.Key key_prop : server_state.getKeys ())
                  {
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
                    String extra = get_client_attributes ? ", SerialNumber=" + server_state.getClientAttributeValues ().get (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER).iterator ().next () : "";
                    cert_spec.setSubject ("CN=KeyGen2 " + _name.getMethodName() + ", E=john.doe@example.com" +
                                          (otp ? ", OU=OTP Key" : extra));
                    otp = false;
    
                    GregorianCalendar start = new GregorianCalendar ();
                    GregorianCalendar end = (GregorianCalendar) start.clone ();
                    end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);
    
                    PublicKey pub_key =  key_prop.getPublicKey ();
    
                    if (temp_set_private_key)
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
                        KeyPair kp = generator.generateKeyPair();
                        pub_key = kp.getPublic ();
                        gen_private_key = kp.getPrivate ();
                      }
    
                    Vector<X509Certificate> cert_path = new Vector<X509Certificate> ();
                    cert_path.add (new CA ().createCert (cert_spec,
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
                          
                        }, pub_key));

                    if (set_trust_anchor)
                      {
                        for (Certificate certificate : DemoKeyStore.getSubCAKeyStore ().getCertificateChain ("mykey"))
                          {
                            cert_path.add ((X509Certificate) certificate);
                          }
                        key_prop.setTrustAnchor (true);
                      }

                    key_prop.setCertificatePath (cert_path.toArray (new X509Certificate[0]));
    
                    if (temp_set_private_key)
                      {
                        key_prop.setEncryptedPrivateKey (server_crypto_interface.encrypt (gen_private_key.getEncoded ()));
                        temp_set_private_key = false;
                      }
    
                  }
              }
            else
              {
                CredentialDiscoveryResponseDecoder cdrd = (CredentialDiscoveryResponseDecoder) server_xml_cache.parse (xmldata);
                server_state.update (cdrd);
                CredentialDiscoveryResponseDecoder.LookupResult[] lres = cdrd.getLookupResults ();
// TODO verify
                server_state.addPostUnlockKey (plain_unlock_key.server_state.getClientSessionID (), 
                                               plain_unlock_key.server_state.getServerSessionID (),
                                               plain_unlock_key.server_state.getKeys ()[0].getCertificatePath ()[0],
                                               plain_unlock_key.server_km);
              }

            return new ProvisioningFinalizationRequestEncoder (server_state, FIN_PROV_URL).writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally we get the attestested response
        ///////////////////////////////////////////////////////////////////////////////////
        void creFinalizeResponse (byte[] xmldata) throws IOException
          {
            ProvisioningFinalizationResponseDecoder prov_final_response = (ProvisioningFinalizationResponseDecoder) server_xml_cache.parse (xmldata);
            server_state.update (prov_final_response);

            ///////////////////////////////////////////////////////////////////////////////////
            // Just a small consistency check
            ///////////////////////////////////////////////////////////////////////////////////
            ByteArrayOutputStream baos = new ByteArrayOutputStream ();
            new ObjectOutputStream (baos).writeObject (server_state);
            byte[] serialized = baos.toByteArray ();
            try
              {
                ServerState scs = (ServerState) new ObjectInputStream (new ByteArrayInputStream (serialized)).readObject ();
              }
            catch (ClassNotFoundException e)
              {
                throw new IOException (e);
              }
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
                    if (b == '\n')
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
            writeString ("&nbsp;<br><table><tr><td bgcolor=\"#F0F0F0\" style=\"border:solid;border-width:1px;padding:4px\">&nbsp;Pass #" + (++pass) + ":&nbsp;" + xo.element () + "&nbsp;</td></tr></table>&nbsp;<br>");
            writeString (XML2HTMLPrinter.convert (new String (xmldata, "UTF-8")));
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
            writeString ("<b>");
            writeString ("Begin Test (" + _name.getMethodName() + ":" + (++round) + ")</b><br>");
            writeOption ("4096 over 2048 RSA key preference", ask_for_4096);
            writeOption ("RSA key with custom exponent", ask_for_exponent);
            writeOption ("Get client attributes", get_client_attributes);
            writeOption ("Client shows one image preference", image_prefs);
            writeOption ("PUK Protection", puk_protection);
            writeOption ("PIN Protection ", pin_protection);
            writeOption ("PIN Input Method ", input_method != null);
            writeOption ("Device PIN", device_pin_protection);
            writeOption ("Preset PIN", preset_pin);
            writeOption ("Enable PIN Caching", enable_pin_caching);
            writeOption ("PIN patterns", add_pin_pattern);
            writeOption ("Fixed PIN", fixed_pin);
            writeOption ("Privacy Enabled", privacy_enabled);
            writeOption ("ECC Key", ecc_key);
            writeOption ("Server Seed", server_seed);
            writeOption ("PropertyBag", property_bag);
            writeOption ("Symmetric Key", symmetric_key);
            writeOption ("Encryption Key", encryption_key);
            writeOption ("Encrypted Extension", encrypted_extension);
            writeOption ("Delete Protection", delete_protection != null);
            writeOption ("Export Protection", export_protection != null);
            writeOption ("Private Key Import", set_private_key);
            writeOption ("Logotype Option", set_logotype);
            writeOption ("Updatable Session", updatable);
            writeOption ("CloneKeyProtection", clone_key_protection != null);
            writeOption ("UpdateKey", update_key != null);
            writeOption ("DeleteKey", delete_key != null);
            writeOption ("UnlockKey", plain_unlock_key != null);
            writeOption ("ECC KMK", ecc_kmk);
            writeOption ("Multiple Keys", two_keys);
            writeOption ("HTTPS server certificate", https);
            writeOption ("TrustAnchor option", set_trust_anchor);
            writeOption ("Abort URL option", set_abort_url);
            writeOption ("Virtual Machine option", virtual_machine);
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
                xml = fileLogger (server.keyCreRequest (xml));
                xml = fileLogger (client.keyCreResponse (xml));
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
        
        int getFirstKey () throws Exception
          {
            EnumeratedKey ek = new EnumeratedKey ();
            while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
              {
                if (ek.getProvisioningHandle () == client.provisioning_handle)
                  {
                    break;
                  }
              }
            assertTrue ("Missing keys", ek != null);
            return ek.getKeyHandle ();
          }

        
      }

    @Test
    public void StrongRSAPreferences () throws Exception
      {
        ask_for_4096 = true;
        new Doer ().perform ();
      }

    @Test
    public void RSAExponentPreferences () throws Exception
      {
        ask_for_exponent = true;
        new Doer ().perform ();
      }

    @Test
    public void ClientAttributes () throws Exception
      {
        get_client_attributes = true;
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
        fixed_pin = true;
        server_seed = true;
        doer.perform ();
        assertFalse ("PIN Not User Modifiable", sks.getKeyProtectionInfo (doer.getFirstKey ()).getPINUserModifiableFlag ());
      }

    @Test
    public void MultipleKeys () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        two_keys = true;
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
        int key_handle = doer.getFirstKey ();
        ServerState.PropertyBag prop_bag = doer.server.server_state.getKeys ()[0].getPropertyBags ()[0];
        Property[] props1 = sks.getExtension (key_handle, prop_bag.getType ()).getProperties ();
        ServerState.Property[] props2 = prop_bag.getProperties ();
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
        sks.setProperty (key_handle, prop_bag.getType (), props2[w].getName (), props2[w].getValue () + "w2");
        props1 = sks.getExtension (key_handle, prop_bag.getType ()).getProperties ();
        for (int i = 0; i < props1.length; i++)
          {
            assertTrue ("Prop name error", props1[i].getName ().equals (props2[i].getName ()));
            assertTrue ("Prop value error", (i == w) ^ props1[i].getValue ().equals (props2[i].getValue ()));
          }
        sks.setProperty (key_handle, prop_bag.getType (), props2[w].getName (), props2[w].getValue ());
        props1 = sks.getExtension (key_handle, prop_bag.getType ()).getProperties ();
        for (int i = 0; i < props1.length; i++)
          {
            assertTrue ("Prop name error", props1[i].getName ().equals (props2[i].getName ()));
            assertTrue ("Prop value error", props1[i].getValue ().equals (props2[i].getValue ()));
          }
        assertTrue ("HMAC error", ArrayUtil.compare (sks.performHMAC (key_handle,
                                                                      MacAlgorithms.HMAC_SHA1.getURI (),
                                                                      null,
                                                                      USER_DEFINED_PIN, TEST_STRING),
                                                     MacAlgorithms.HMAC_SHA1.digest (OTP_SEED, TEST_STRING)));
      }

    @Test
    public void Logotype () throws Exception
      {
        Doer doer = new Doer ();
        set_logotype = true;
        doer.perform ();
      }

   @Test
    public void ImportSymmetricKey () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        encryption_key = true;
        symmetric_key = true;
        doer.perform ();
        int key_handle = doer.getFirstKey ();
        byte[] iv = null;
        byte[] enc = sks.symmetricKeyEncrypt (key_handle,
                                              SymEncryptionAlgorithms.AES256_CBC.getURI (),
                                              true,
                                              iv,
                                              USER_DEFINED_PIN,
                                              TEST_STRING);
        assertTrue ("Encrypt/decrypt error", ArrayUtil.compare (sks.symmetricKeyEncrypt (key_handle,
                                                                                         SymEncryptionAlgorithms.AES256_CBC.getURI (),
                                                                                         false,
                                                                                         iv,
                                                                                         USER_DEFINED_PIN, 
                                                                                         enc),
                                                                                         TEST_STRING));
        assertFalse ("PIN Cached", sks.getKeyProtectionInfo (key_handle).getEnablePINCachingFlag ());
      }

    @Test
    public void DevicePIN () throws Exception
      {
        Doer doer = new Doer ();
        device_pin_protection = true;
        set_abort_url = true;
        doer.perform ();
      }

    @Test
    public void PresetPIN () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        preset_pin = true;
        enable_pin_caching = true;
        input_method = InputMethod.TRUSTED_GUI;
        doer.perform ();
        assertFalse ("PIN Not User Modifiable", sks.getKeyProtectionInfo (doer.getFirstKey ()).getPINUserModifiableFlag ());
        assertTrue ("PIN Not Cached", sks.getKeyProtectionInfo (doer.getFirstKey ()).getEnablePINCachingFlag ());
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
                                                    PREDEF_SERVER_PIN,
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
        int key_handle = doer2.getFirstKey ();
        KeyAttributes ka = sks.getKeyAttributes (key_handle);
        byte[] result = sks.signHashedData (key_handle,
                                            SignatureAlgorithms.RSA_SHA256.getURI (),
                                            null,
                                            PREDEF_SERVER_PIN,
                                            HashAlgorithms.SHA256.digest (TEST_STRING));
        Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
        verify.initVerify (ka.getCertificatePath ()[0]);
        verify.update (TEST_STRING);
        assertTrue ("Bad signature", verify.verify (result));
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
    public void ImportPrivateKey () throws Exception
      {
        Doer doer = new Doer ();
        set_private_key = true;
        pin_protection = true;
        doer.perform ();
        int key_handle = doer.getFirstKey ();
        byte[] result = sks.signHashedData (key_handle,
                                            SignatureAlgorithms.RSA_SHA256.getURI (),
                                            null,
                                            USER_DEFINED_PIN,
                                            HashAlgorithms.SHA256.digest (TEST_STRING));
        Signature sign = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
        sign.initSign (doer.server.gen_private_key);
        sign.update (TEST_STRING);
        assertTrue ("Bad signature", ArrayUtil.compare (sign.sign (), result));
      }

    @Test
    public void ExportProtection () throws Exception
      {
        for (ExportProtection exp_pol : ExportProtection.values ())
          {
            Doer doer = new Doer ();
            export_protection = exp_pol;
            pin_protection = exp_pol == ExportProtection.PIN || exp_pol == ExportProtection.PUK;
            puk_protection = exp_pol == ExportProtection.PUK;
            ecc_key = true;
            doer.perform ();
            KeyProtectionInfo kpi = sks.getKeyProtectionInfo (doer.getFirstKey ());
            assertTrue ("Export prot", kpi.getExportProtection () == exp_pol);
          }
      }

    @Test
    public void DeleteProtection () throws Exception
      {
        for (DeleteProtection del_pol : DeleteProtection.values ())
          {
            Doer doer = new Doer ();
            pin_protection = del_pol == DeleteProtection.PIN || del_pol == DeleteProtection.PUK;
            puk_protection = del_pol == DeleteProtection.PUK;
            delete_protection = del_pol;
            ecc_key = true;
            doer.perform ();
            KeyProtectionInfo kpi = sks.getKeyProtectionInfo (doer.getFirstKey ());
            assertTrue ("Delete prot", kpi.getDeleteProtection () == del_pol);
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
        int key_handle = doer.getFirstKey ();
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp256r1");
        generator.initialize (eccgen, new SecureRandom ());
        KeyPair kp = generator.generateKeyPair ();
        KeyAttributes ka = sks.getKeyAttributes (key_handle);
        byte[] z = sks.keyAgreement (key_handle,
                                     KeyGen2URIs.SPECIAL_ALGORITHMS.ECDH_RAW,
                                     null,
                                     USER_DEFINED_PIN, 
                                     (ECPublicKey)kp.getPublic ());
        KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDH");
        key_agreement.init (kp.getPrivate ());
        key_agreement.doPhase (ka.getCertificatePath ()[0].getPublicKey (), true);
        byte[] Z = key_agreement.generateSecret ();
        assertTrue ("DH fail", ArrayUtil.compare (z, Z));
      }

    @Test
    public void UnlockKey () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        pin_protection = true;
        ecc_key = true;
        doer1.perform ();
        int key_handle = doer1.getFirstKey ();
        for (int i = 1; i <= doer1.server.pin_retry_limit; i++)
          {
            try
              {
                sks.signHashedData (key_handle,
                                    SignatureAlgorithms.ECDSA_SHA256.getURI (),
                                    null,
                                    BAD_PIN,
                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                fail ("Bad PIN should not work");
              }
            catch (SKSException e)
              {
                assertFalse ("Locked", sks.getKeyProtectionInfo (key_handle).isPINBlocked () ^ (i == doer1.server.pin_retry_limit));
              }
          }

        updatable = false;
        pin_protection = false;
        ecc_key = false;
        plain_unlock_key = doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        assertFalse ("UnLocked", sks.getKeyProtectionInfo (key_handle).isPINBlocked ());
      }

    @Test
    public void PrivacyEnabled () throws Exception
      {
        Doer doer1 = new Doer ();
        privacy_enabled = true;
        updatable = true;
        pin_protection = true;
        ecc_key = true;
        doer1.perform ();
        int key_handle = doer1.getFirstKey ();
        for (int i = 1; i <= doer1.server.pin_retry_limit; i++)
          {
            try
              {
                sks.signHashedData (key_handle,
                                    SignatureAlgorithms.ECDSA_SHA256.getURI (),
                                    null,
                                    BAD_PIN,
                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                fail ("Bad PIN should not work");
              }
            catch (SKSException e)
              {
                assertFalse ("Locked", sks.getKeyProtectionInfo (key_handle).isPINBlocked () ^ (i == doer1.server.pin_retry_limit));
              }
          }

        updatable = false;
        pin_protection = false;
        ecc_key = false;
        plain_unlock_key= doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        assertFalse ("UnLocked", sks.getKeyProtectionInfo (key_handle).isPINBlocked ());
        assertTrue ("PIN User Modifiable", sks.getKeyProtectionInfo (key_handle).getPINUserModifiableFlag ());
      }

    @Test
    public void TrustAnchor () throws Exception
      {
        Doer doer = new Doer ();
        set_trust_anchor = true;
        doer.perform ();
        X509Certificate[] cert_path = sks.getKeyAttributes (doer.getFirstKey ()).getCertificatePath ();
        assertTrue ("Path Length", CertificateUtil.isTrustAnchor (cert_path[cert_path.length - 1]));
      }

    @Test
    public void VirtualMachine () throws Exception
      {
        Doer doer = new Doer ();
        virtual_machine = true;
        doer.perform ();
      }

    @Test
    public void MassiveUserPINCollection () throws Exception
      {
        assertTrue (PINCheck (PassphraseFormat.ALPHANUMERIC, null, "AB123"));
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, null, "1234"));
        assertTrue (PINCheck (PassphraseFormat.STRING, null, "azAB13.\n"));
        assertTrue (PINCheck (PassphraseFormat.BINARY, null, "12300234FF"));
        assertTrue (PINCheck (PassphraseFormat.BINARY, null, "12300234ff"));
        assertFalse (PINCheck (PassphraseFormat.BINARY, null, "3034ff"));
        assertFalse (PINCheck (PassphraseFormat.BINARY, null, "12300234fp"));

        assertFalse (PINCheck (PassphraseFormat.ALPHANUMERIC, null, "ab123"));  // Lowercase 
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, null, "AB1234"));      // Alpha

        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1234"));      // Up seq
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "8765"));      // Down seq
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1235"));      // No seq
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1345"));      // No seq

        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "1232"));      // No two in row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "11345"));      // Two in a row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "13455"));      // Two in a row

        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "11232"));      // No two in row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "111345"));      // Three in a row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "134555"));      // Three in a row
        
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "1235"));      // No seq or three in a row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "6789"));      // Seq
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "1115"));      // Three in a row

        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "1476"));      // Bad combo
        assertFalse (PINCheck (PassphraseFormat.BINARY, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "12300234FF"));      // Bad combo

        assertTrue (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2aZ."));
        assertTrue (PINCheck (PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "AB34"));

        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2aZA"));  // Non alphanum missing
        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "a.jZ"));  // Number missing
        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2 ZA"));  // Lowercase missing
        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2a 6"));  // Uppercase missing

        assertFalse (PINCheck (PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "ABCK")); // Missing number
        assertFalse (PINCheck (PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "1235")); // Missing alpha
        
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.REPEATED}, "1345"));
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.REPEATED}, "1315"));  // Two of same

        PINGroupCheck (Grouping.NONE, new AppUsage[] {AppUsage.AUTHENTICATION}, new String[] {"1234"}, new int[] {0}, false);
        PINGroupCheck (Grouping.NONE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234", "1234"}, new int[] {0, 1}, false);
        PINGroupCheck (Grouping.NONE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234", "1235"}, new int[] {0, 1}, false);
        PINGroupCheck (Grouping.SHARED, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234", "1234"}, new int[] {0, 1}, true);
        PINGroupCheck (Grouping.SHARED, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE, AppUsage.SIGNATURE}, new String[] {"1234"}, new int[] {0, 0, 0}, false);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234"}, new int[] {0, 0}, true);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234","2345"}, new int[] {0, 1}, false);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234","1234"}, new int[] {0, 1}, true);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.SIGNATURE, AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234","2345"}, new int[] {0, 1, 0}, false);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.SIGNATURE, AppUsage.AUTHENTICATION, AppUsage.SIGNATURE, AppUsage.ENCRYPTION}, new String[] {"1234","2345","7777"}, new int[] {0, 1, 0, 2}, false);
        PINGroupCheck (Grouping.SIGNATURE_PLUS_STANDARD, new AppUsage[] {AppUsage.SIGNATURE, AppUsage.AUTHENTICATION, AppUsage.SIGNATURE, AppUsage.ENCRYPTION}, new String[] {"2345","1234"}, new int[] {0, 1, 0, 1}, false);
        PINGroupCheck (Grouping.SIGNATURE_PLUS_STANDARD, new AppUsage[] {AppUsage.SIGNATURE, AppUsage.AUTHENTICATION, AppUsage.SIGNATURE, AppUsage.ENCRYPTION}, new String[] {"2345","2345"}, new int[] {0, 1, 0, 1}, true);
      }
  }
