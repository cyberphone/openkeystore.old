package org.webpki.sks;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;

import java.util.Vector;
import java.util.Date;
import java.util.HashMap;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.CallableStatement;
import java.sql.ResultSet;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;
import org.webpki.util.StringUtil;
import org.webpki.util.DebugFormatter;
import org.webpki.util.WrappedException;

import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SignerInterface;

import org.webpki.keygen2.CredentialDeploymentRequestDecoder;
import org.webpki.keygen2.PlatformNegotiationRequestDecoder;
import org.webpki.keygen2.PlatformNegotiationResponseEncoder;
import org.webpki.keygen2.KeyInitializationResponseEncoder;
import org.webpki.keygen2.KeyInitializationRequestDecoder;
import org.webpki.keygen2.PassphraseFormats;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.InputMethods;
import org.webpki.keygen2.PatternRestrictions;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.KeyAttestationUtil;
import org.webpki.keygen2.SymmetricKeyDecrypter;
import org.webpki.keygen2.BasicCapabilities;


public class Provisioning
  {
    int user_id;

    DebugCallback debug_callback;
    
    SecureKeyStore sks;

    public interface DebugCallback
      {
        void print (String message) throws IOException;
      }

    private void debugOutput (String message) throws IOException
      {
        if (debug_callback != null)
          {
            debug_callback.print (message);
          }
      }


    public Provisioning (SecureKeyStore sks) throws IOException
      {
        this.sks = sks;
      }


    public Provisioning (SecureKeyStore sks, DebugCallback debug_callback) throws IOException
      {
        this (sks);
        this.debug_callback = debug_callback;
      }


    private int createProvisioning (String client_session_id,
                                    String server_session_id,
                                    String issuer_uri) throws IOException, SQLException
      {
        int inst = 0;
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt =
             conn.prepareStatement ("INSERT INTO PROVISIONINGS (ClientSession, ServerSession, IssuerURI, UserID) VALUES (?,?,?,?)",
                                    PreparedStatement.RETURN_GENERATED_KEYS);
        pstmt.setString (1, client_session_id);
        pstmt.setString (2, server_session_id);
        pstmt.setString (3, issuer_uri);
        pstmt.setInt (4, user_id);
        pstmt.executeUpdate ();
        ResultSet rs = pstmt.getGeneratedKeys ();
        if (rs.next ())
          {
            inst = rs.getInt (1);
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        if (inst == 0)
          {
            throw new IOException ("Couldn't create ProvisionID!");
          }
        return inst;
      }



    class DeviceSigner implements SignerInterface
      {
        X509Certificate[] cert_path;

        private DeviceSigner () throws IOException
          {
          }


        public X509Certificate[] prepareSigning (boolean fullpath) throws IOException
          {
            cert_path = sks.getDeviceCertificatePath ();
            return cert_path;
          }


        public byte[] signData (byte[] data, SignatureAlgorithms algorithm) throws IOException
          {
            return sks.deviceKeyDigestSign (Digester.digestAll (data, algorithm), algorithm);
          }


        public CertificateInfo getSignerCertificateInfo () throws IOException
          {
            return new CertificateInfo (cert_path[0]);
          }


        public boolean authorizationFailed() throws IOException
          {
             return false;
          }
        

      }


    class DeviceDecrypter implements SymmetricKeyDecrypter
      {
        private DeviceDecrypter ()
          {
          }

        public byte[] decrypt (byte[] data, X509Certificate optional_key_id) throws IOException
          {
            return sks.deviceKeyDecrypt (data, AsymEncryptionAlgorithms.RSA_PKCS_1);
          }
      }
  


    void createUserKey (KeyInitializationRequestDecoder decoder,
                        KeyInitializationRequestDecoder.CreateKey key_properties,
                        String pin_value,
                        KeyInitializationResponseEncoder encoder,
                        BasicCapabilities capabilities,
                        int provision_id,
                        String replace_key_id) throws IOException, SQLException, GeneralSecurityException
      {
        KeyInitializationRequestDecoder.KeyAlgorithmData key_alg = key_properties.getKeyAlgorithmData ();
        SecureKeyStore.AttestedKeyPair key_pair = null;
        X509Certificate archival_key = key_properties.getPrivateKeyArchivalKey ();
            byte[] nonce = KeyAttestationUtil.createKA1Nonce (key_properties.getID (),
                                                              decoder.getClientSessionID (),
                                                              decoder.getServerSessionID ());
            
            SymEncryptionAlgorithms encrytion_algorithm = SymEncryptionAlgorithms.AES256_CBC;
            if (!capabilities.getSymmetricKeyEncryptionAlgorithms ().isEmpty () &&
                !capabilities.getSymmetricKeyEncryptionAlgorithms ().contains (SymEncryptionAlgorithms.AES256_CBC))
              {
                encrytion_algorithm = SymEncryptionAlgorithms.AES128_CBC;
              }

            AsymEncryptionAlgorithms key_wrap_algorithm = AsymEncryptionAlgorithms.RSA_PKCS_1;

            key_pair = sks.
                                generateAttestedKeyPair (key_alg,
                                KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1,
                                key_properties.isExportable (),
                                key_properties.getKeyUsage (),
                                nonce,
                                archival_key == null ? null : archival_key.getPublicKey ().getEncoded (),
                                KeyGen2URIs.FORMATS.PKCS8_PRIVATE_KEY_INFO,
                                encrytion_algorithm,
                                key_wrap_algorithm);

            encoder.addAttestedKey (key_pair.getPublicKey (),
                                    (key_pair).getAttestSignature (),
                                    key_properties.getID (),
                                    archival_key == null ? null : 
                                      new KeyInitializationResponseEncoder.KeyArchivalData
                                         (key_pair.getEncryptedPrivateKey (),
                                          key_pair.getWrappedEncryptionKey (),
                                          encrytion_algorithm,
                                          key_wrap_algorithm));

        String pin_policy_id = null;
        byte[] pin_blob = null;
        String pin_try_count = null;
        boolean preset_pin_flag = false;
        if (key_properties.getPINPolicy () != null)
          {
            KeyInitializationRequestDecoder.PINPolicy pin_policy = key_properties.getPINPolicy ();
            pin_policy_id = (String) pin_policy.getUserData ();
            if (key_properties.getPresetPIN () == null)
              {
                pin_blob = KeyUtil.getPassphrase (pin_value, pin_policy.getFormat ());
              }
            else
              {
                preset_pin_flag = true;
              }
            pin_try_count = String.valueOf (pin_policy.getRetryLimit ());
          }
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement ("INSERT INTO USERKEYS (UserID, " +
                                                                               "Exportable, "+
                                                                               "Archived, " +
                                                                               "CertPath, " +
                                                                               "PrivateKey, " +
                                                                               "PINPolicyID, " +
                                                                               "PINTryCount, " +
                                                                               "PINValue) " +
                                                         "VALUES (?,?,?,?,?,?,?,?)",
                                                         PreparedStatement.RETURN_GENERATED_KEYS);
        pstmt.setInt (1, user_id);
        pstmt.setBoolean (2, key_properties.isExportable ());
        pstmt.setBoolean (3, key_properties.getPrivateKeyArchivalKey () != null);
        pstmt.setBytes (4, null);
        pstmt.setBytes (5, key_pair.getPrivateKeyHandle ());
        pstmt.setString (6, pin_policy_id);
        pstmt.setString (7, pin_try_count);
        pstmt.setBytes (8, pin_blob);
        pstmt.executeUpdate ();
        int key_id = 0;
        ResultSet rs = pstmt.getGeneratedKeys ();
        if (rs.next ())
          {
            key_id = rs.getInt (1);
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        if (key_id == 0)
          {
            throw new IOException ("Couldn't get KeyID!");
          }
        if (preset_pin_flag)
          {
            key_properties.getPresetPIN ().setLocalReferenceObject (key_id);
          }
        debugOutput ((key_alg instanceof KeyInitializationRequestDecoder.RSA ?
                 "RSA keypair with size " + ((KeyInitializationRequestDecoder.RSA)key_alg).getKeySize () :
                 "ECC keypair with curve "+ ((KeyInitializationRequestDecoder.EC)key_alg).getNamedCurve ().getOID ()) +
                    " and KEY_ID=" + key_id + " created" +
                     (archival_key == null ? "" : " with archival option"));
        if (pin_blob != null)
          {
            debugOutput ("PIN for key with KEY_ID=" + key_id + " value set to '" + pin_value + "'");
          }

/*
    ProvisionID   INT            NOT NULL,                                 -- Owning provisioning session
    KeyID         INT            NOT NULL,                                 -- Local KeyID of provisioned key
    KeyUsage      INT            NOT NULL,                                 -- Ordinal (0..n) of "KeyGen2KeyUsage"
    PublicKey     BLOB           NOT NULL,                                 -- The generated public key serialized
    ServerKeyID   VARCHAR (256)  NOT NULL,                                 -- The server's symbolic name
    ReplaceKeyID  INT            NULL,                                     -- Defined => Original KeyID (for update)
*/
        conn = KeyUtil.getDatabaseConnection ();
        pstmt = conn.prepareStatement ("INSERT INTO PROVISIONEDKEYS (ProvisionID, " +
                                                                    "KeyID, " +
                                                                    "KeyUsage, " +
                                                                    "PublicKey, " +
                                                                    "ServerKeyID, " +
                                                                    "ReplaceKeyID) " +
                                       "VALUES (?,?,?,?,?,?)");
        pstmt.setInt (1, provision_id);
        pstmt.setInt (2, key_id);
        pstmt.setInt (3, key_properties.getKeyUsage ().ordinal ());
        pstmt.setBytes (4, key_pair.getPublicKey ().getEncoded ());
        pstmt.setString (5, key_properties.getID ());
        pstmt.setString (6, replace_key_id);
        pstmt.executeUpdate ();
        pstmt.close ();
        conn.close ();
      }

    class ProvCertSel extends CertificateSupport
      {
        PublicKey public_key;
        javax.security.auth.x500.X500Principal issuer;

        ProvCertSel (SecureKeyStore sks, X509Certificate ca_certificate) throws GeneralSecurityException
          {
            super (sks);
            public_key = ca_certificate.getPublicKey ();
            issuer = ca_certificate.getSubjectX500Principal ();
          }


        boolean wantAsymmetricKeys ()
          {
            return false;
          }

        Integer[] getFilteredAndCertified (CertificateFilter filter) throws IOException
          {
            Vector<Integer> actual = new Vector<Integer> ();
            for (SelectedCertificate cert : getCertificateSelection (filter, null))
              {
                try
                  {
                    cert.certificate.verify (public_key);
                    if (cert.certificate.getIssuerX500Principal ().equals (issuer))
                      {
                        actual.add (cert.key_id);
                      }
                  }
                catch (GeneralSecurityException gse)
                  {
                  }
              }
            return actual.toArray (new Integer[0]);
          }
      }


    void deleteKeys (Integer[] keys, int provision_id) throws IOException, SQLException
      {
        Connection conn = KeyUtil.getDatabaseConnection ();
        for (int key_id : keys)
          {
            PreparedStatement pstmt = conn.prepareStatement ("INSERT INTO DELETEDKEYS (ProvisionID, KeyID) " +
                                           "VALUES (?,?)");
            pstmt.setInt (1, provision_id);
            pstmt.setInt (2, key_id);
            pstmt.executeUpdate ();
            pstmt.close ();
            debugOutput ("Key with KEY_ID=" + key_id + " was marked for deletion");
          }
        conn.close ();
      }


    public KeyInitializationResponseEncoder initializeProvisioning (KeyInitializationRequestDecoder keyopreq_decoder,
                                                               PlatformNegotiationRequestDecoder platform_decoder,
                                                               PlatformNegotiationResponseEncoder platform_encoder,
                                                               PINProvisioning pin_provisioning,
                                                               X509Certificate optional_server_certificate)
    throws IOException, SQLException, GeneralSecurityException
      {
        KeyInitializationResponseEncoder encoder = 
            new KeyInitializationResponseEncoder (keyopreq_decoder.getClientSessionID (),
                                             keyopreq_decoder.getServerSessionID (),
                                             platform_decoder.getSubmitURL (),
                                             keyopreq_decoder.getSubmitURL (),
                                             keyopreq_decoder.getServerTime (),
                                             new Date(),
                                             optional_server_certificate);

        encoder.setServerCookie (keyopreq_decoder.getServerCookie ());

        BasicCapabilities capabilities = platform_encoder.getBasicCapabilities ();

        int provision_id = createProvisioning (keyopreq_decoder.getClientSessionID (),
                                               keyopreq_decoder.getServerSessionID (),
                                               platform_decoder.getSubmitURL ());
        debugOutput ("Provisioning session #" + provision_id + " initiated");

        String pin_value = null;

        for (KeyInitializationRequestDecoder.RequestObjects ro : keyopreq_decoder.getRequestObjects ())
          {
            if (ro instanceof KeyInitializationRequestDecoder.CreateKey)
              {

                // Standard key generation request

                KeyInitializationRequestDecoder.CreateKey rk = (KeyInitializationRequestDecoder.CreateKey) ro;
                if (rk.isStartOfPUKPolicy ())
                  {
                    KeyInitializationRequestDecoder.PUKPolicy puk_policy = rk.getPUKPolicy ();
                    int puk_policy_id = createPUKPolicy (puk_policy.getRetryLimit (), puk_policy.getFormat ());
                    puk_policy.setUserData (puk_policy_id);
                    puk_policy.setLocalReferenceObject (puk_policy_id);
                  }
                if (rk.isStartOfPINPolicy ())
                  {
                    KeyInitializationRequestDecoder.PINPolicy pin_policy = rk.getPINPolicy ();
                    pin_value = pin_provisioning.getValue (pin_policy);
                    KeyInitializationRequestDecoder.PUKPolicy puk_policy = rk.getPUKPolicy ();
                    int puk_policy_id = puk_policy.getUserData () == null ?
                        getDevicePUKPolicyID () : (Integer)puk_policy.getUserData ();
                    pin_policy.setUserData (
                        String.valueOf (
                            createPINPolicy (pin_policy.getRetryLimit (),
                                             pin_policy.getMinLength (),
                                             pin_policy.getMaxLength (),
                                             pin_policy.getFormat (),
                                             pin_policy.getGrouping (),
                                             pin_policy.getPatternRestrictions (),  // May be null
                                             pin_policy.getInputMethod (),
                                             pin_policy.getCachingSupport (),
                                             puk_policy_id)));
                    debugOutput ("PIN policy object with PIN_ID=" + (String)pin_policy.getUserData () + " created");
                  }

                createUserKey (keyopreq_decoder, rk, pin_value, encoder, capabilities, provision_id, null);

              }
            else
              {
     
                // This MUST be a key management operation..

                X509Certificate ca_cert = ((KeyInitializationRequestDecoder.ManageObject) ro).getCACertificate ();
                Integer selected_single_key = null;
                if (ro instanceof KeyInitializationRequestDecoder.CertificateReference)
                  {
                    Integer[] keys = new ProvCertSel (sks, ca_cert).getFilteredAndCertified (
                             new CertificateFilter (((KeyInitializationRequestDecoder.CertificateReference) ro).getCertificateSHA1 () /* byte[] sha1 */ , 
                                                    null /* String issuer_regex */,
                                                    null /* String subject_regex */,
                                                    null /* String email_address */,
                                                    null /* BigInteger serial */,
                                                    null /* String policy_oid */,
                                                    null /* KeyContainerTypes[] containers */,
                                                    null /* KeyGen2KeyUsage key_usage */,
                                                    null /* String ext_key_usage_oid */));
                    if (keys.length == 0)
                      {
                        if (ro instanceof KeyInitializationRequestDecoder.DeleteKey &&
                            ((KeyInitializationRequestDecoder.DeleteKey) ro).isConditional ())
                          {
                            continue;
                          }
                        throw new IOException ("Missing key: " + DebugFormatter.getHexString (((KeyInitializationRequestDecoder.CertificateReference) ro).getCertificateSHA1 ()));
                      }
                    selected_single_key = keys[0];
                  }


                // "Execute" key management ops...

                if (ro instanceof KeyInitializationRequestDecoder.DeleteKey)
                  {
                    deleteKeys (new Integer[]{selected_single_key}, provision_id);
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.DeleteKeysByContent)
                  {
                    KeyInitializationRequestDecoder.DeleteKeysByContent dkbc = (KeyInitializationRequestDecoder.DeleteKeysByContent) ro;
                    deleteKeys (new ProvCertSel (sks, ca_cert).getFilteredAndCertified (
                             new CertificateFilter (null /* byte[] sha1 */ , 
                                                    null /* String issuer_regex */,
                                                    null /* String subject_regex */,
                                                    dkbc.getEmailAddress () /* String email_address */,
                                                    null /* BigInteger serial */,
                                                    null /* String policy_oid */,
                                                    null /* KeyContainerTypes[] containers */,
                                                    null /* KeyGen2KeyUsage key_usage */,
                                                    null /* String ext_key_usage_oid */)),
                                provision_id);
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.CloneKey)
                  {
/*
                    s.append ("CK=" + ca_name);
                    getBaseKeyData (s, ((KeyInitializationRequestDecoder.CloneKey) ro).getCreateKeyProperties ());
*/
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.ReplaceKey)
                  {
/*
                    s.append ("RK=" + ca_name);
                    getBaseKeyData (s, ((KeyInitializationRequestDecoder.ReplaceKey) ro).getCreateKeyProperties ());
*/
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.UpdatePINPolicy)
                  {
/*
                    KeyInitializationRequestDecoder.UpdatePINPolicy upg = (KeyInitializationRequestDecoder.UpdatePINPolicy) ro;
                    s.append ("UPIN=" + ca_name);
                    s.append (" PIN Group=" + upg.getPINPolicy ().getFormat ());
*/
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.UpdatePUKPolicy)
                  {
/*
                    KeyInitializationRequestDecoder.UpdatePUKPolicy upg = (KeyInitializationRequestDecoder.UpdatePUKPolicy) ro;
                    s.append ("UPUK=" + ca_name);
                    s.append (" PUK Group=" + upg.getPUKPolicy ().getFormat () + " V=" + upg.getPUKPolicy ().getValue ());
*/
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.UpdatePresetPIN)
                  {
/*
                    KeyInitializationRequestDecoder.UpdatePresetPIN upg = (KeyInitializationRequestDecoder.UpdatePresetPIN) ro;
                    s.append ("UPPRSET=" + ca_name);
                    s.append (" V=" + upg.getPresetPIN ().getValue ());
*/
                  }
              }
          }
/*
        if (kgrd.isSigned ())
          {
            JKSCAVerifier verifier = new JKSCAVerifier (DemoKeyStore.getCAKeyStore ());
            verifier.setTrustedRequired (false);
            kgrd.verifySignature (verifier);
            System.out.println ("\nSIGNATURE\n" + verifier.getSignerCertificateInfo ().toString () + "\nSIGNATURE");
          }
    */
        if (keyopreq_decoder.getDeferredCertificationFlag ())
          {
            ByteArrayOutputStream baos = new ByteArrayOutputStream ();
            ObjectOutputStream oos = new ObjectOutputStream (baos);
            oos.writeObject (keyopreq_decoder);
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("UPDATE PROVISIONINGS SET SavedRequest=? WHERE ProvisionID=?");
            pstmt.setBytes (1, baos.toByteArray ());
            pstmt.setInt (2, provision_id);
            pstmt.executeUpdate ();
            pstmt.close ();
            conn.close ();
          } 
        encoder.createEndorsementKeySignature (new DeviceSigner ());
        return encoder;
      }

    class ProvisionedKey
      {
        KeyGen2KeyUsage key_usage;

        int key_id;

        byte[] public_key;

        int replace_key_id;  // 0 = none
      }

    HashMap<String,ProvisionedKey> getProvisionedKeys (CredentialDeploymentRequestDecoder decoder)
    throws IOException, SQLException
      {
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement ("SELECT ProvisionID FROM " +
                                                         "PROVISIONINGS WHERE " +
                                                         "ServerSession=? AND ClientSession=? AND UserID=?");
        pstmt.setString (1, decoder.getServerSessionID ());
        pstmt.setString (2, decoder.getClientSessionID ());
        pstmt.setInt (3, user_id);
        ResultSet rs = pstmt.executeQuery ();
        int provision_id = 0;
        if (rs.next ())
          {
            provision_id = rs.getInt (1);
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        if (provision_id == 0)
          {
            throw new IOException ("Couldn't find provisioning instance!");
          }

        HashMap<String,ProvisionedKey> provisioned_keys = new HashMap<String,ProvisionedKey> ();

/*
    ProvisionID   INT            NOT NULL,                                 -- Owning provisioning session
    KeyID         INT            NOT NULL,                                 -- Local KeyID of provisioned key
    KeyUsage      INT            NOT NULL,                                 -- Ordinal (0..n) of "KeyGen2KeyUsage"
    PublicKey     BLOB           NOT NULL,                                 -- The generated public key serialized
    ServerKeyID   VARCHAR (256)  NOT NULL,                                 -- The server's symbolic name
    ReplaceKeyID  INT            NULL,                                     -- Defined => Original KeyID (for update)
*/
        conn = KeyUtil.getDatabaseConnection ();
        pstmt = conn.prepareStatement ("SELECT KeyID, " +
                                              "KeyUsage, " +
                                              "PublicKey, " +
                                              "ServerKeyID, " +
                                              "ReplaceKeyID " +
                                       "FROM PROVISIONEDKEYS WHERE ProvisionID=?");
        pstmt.setInt (1, provision_id);
        rs = pstmt.executeQuery ();
        while (rs.next ())
          {
            ProvisionedKey pk = new ProvisionedKey ();
            pk.key_id = rs.getInt (1);
            pk.key_usage = KeyGen2KeyUsage.values ()[rs.getInt (2)];
            pk.public_key = rs.getBytes (3);
            String server_key_id = rs.getString (4);
            pk.replace_key_id = rs.getInt (5);
            provisioned_keys.put (server_key_id, pk);
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        return provisioned_keys;
      }


    public PlatformNegotiationResponseEncoder negotiate (PlatformNegotiationRequestDecoder decoder)
    throws IOException
      {
        String client_session_id = "S." + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());
        PlatformNegotiationResponseEncoder encoder =
           new PlatformNegotiationResponseEncoder (decoder.getServerSessionID (), client_session_id);
        encoder.setServerCookie (decoder.getServerCookie ());
        if (decoder.getBasicCapabilities ().getSymmetricKeyEncryptionAlgorithms ().contains (SymEncryptionAlgorithms.AES128_CBC))
          {
            encoder.getBasicCapabilities ().addSymmetricKeyEncryptionAlgorithm (SymEncryptionAlgorithms.AES128_CBC);
          }
        if (decoder.getBasicCapabilities ().getSymmetricKeyEncryptionAlgorithms ().contains (SymEncryptionAlgorithms.AES256_CBC))
          {
            encoder.getBasicCapabilities ().addSymmetricKeyEncryptionAlgorithm (SymEncryptionAlgorithms.AES256_CBC);
          }
        if (!decoder.getBasicCapabilities ().getSymmetricKeyEncryptionAlgorithms ().isEmpty () &&
             encoder.getBasicCapabilities ().getSymmetricKeyEncryptionAlgorithms ().isEmpty ())
          {
            throw new IOException ("No matching symmetric key algorithm");
          }
        return encoder;
      }


    public void finalizeProvisioning (CredentialDeploymentRequestDecoder credep_decoder,
                                      KeyInitializationRequestDecoder keyopreq_decoder)
    throws IOException, SQLException, GeneralSecurityException, ClassNotFoundException
      {
        if (keyopreq_decoder == null)
          {
            byte[] blob = null;
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("SELECT SavedRequest FROM " +
                                                             "PROVISIONINGS WHERE " +
                                                             "ServerSession=? AND ClientSession=? AND UserID=?");
            pstmt.setString (1, credep_decoder.getServerSessionID ());
            pstmt.setString (2, credep_decoder.getClientSessionID ());
            pstmt.setInt (3, user_id);
            ResultSet rs = pstmt.executeQuery ();
            if (rs.next ())
              {
                blob = rs.getBytes (1);
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
            if (blob == null)
              {
                throw new IOException ("Couldn't get saved request for " + 
                                       credep_decoder.getServerSessionID () +
                                       " and " +
                                       credep_decoder.getClientSessionID ());
              }
            keyopreq_decoder = (KeyInitializationRequestDecoder) new ObjectInputStream (new ByteArrayInputStream (blob)).readObject ();
          }
        credep_decoder.setDecrypter (new DeviceDecrypter ());
        credep_decoder.setKeyOperationRequestDecoder (keyopreq_decoder);

        for (CredentialDeploymentRequestDecoder.PresetValue pv : credep_decoder.getPresetValues ())
          {
            if (pv.isPUK ())
              {
                updatePUKPolicy ((Integer)pv.getLocalReferenceObject (), pv.getValue ());
              }
            else
              {
                UpdatePINValue ((Integer)pv.getLocalReferenceObject (), pv.getValue ());
              }
          } 
        HashMap<String,ProvisionedKey> provisioned_keys = getProvisionedKeys (credep_decoder);
        for (CredentialDeploymentRequestDecoder.CertifiedPublicKey cred : credep_decoder.getCertifiedPublicKeys ())
          {
            ProvisionedKey pk = provisioned_keys.get (cred.getID ());
            if (pk == null)
              {
                throw new IOException ("Missing key: " + cred.getID ());
              }
            if ((pk.key_usage == KeyGen2KeyUsage.SYMMETRIC_KEY) != cred.hasSymmetricKey ())
              {
                throw new IOException ("Wrong usage of " + pk.key_usage.toString () + " with resp. to piggy-back-symmetric key: " + cred.getID ());
              }
            X509Certificate[] cert_path = cred.getCertificatePath ();
            if (!ArrayUtil.compare (pk.public_key, cert_path[0].getPublicKey ().getEncoded ()))
              {
                throw new IOException ("Bad public key: " + cred.getID ());
              }
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("UPDATE USERKEYS SET CertPath=?, FriendlyName=? WHERE KeyID=?");
            pstmt.setBytes (1, KeyUtil.createDBCertificatePath (cert_path));
            pstmt.setString (2, cred.getFriendlyName () == null ?
                  new CertificateInfo (cert_path[0]).getSubjectCommonName (): cred.getFriendlyName ());
            pstmt.setInt (3, pk.key_id);
            pstmt.executeUpdate ();
            pstmt.close ();
            conn.close ();
            debugOutput ("Certificate with fingerprint=" + DebugFormatter.getHexString (new CertificateInfo (cert_path[0]).getCertificateHash ()) + " deployed to KEY_ID=" + pk.key_id);

            if (cred.hasSymmetricKey ())
              {
                deployPiggybackedSymmetricKey (cred, credep_decoder, pk.key_id);
              }

            KeyDescriptor key_descriptor = new KeyMetadataProvider (sks).getKeyDescriptor (pk.key_id);

            for (CredentialDeploymentRequestDecoder.PropertyBag property_bag : cred.getPropertyBags ())
              {
                deployPropertyBag (property_bag, key_descriptor);
              }

            for (CredentialDeploymentRequestDecoder.Extension extension : cred.getExtensions ())
              {
                deployExtension (extension, key_descriptor);
              }
            for (CredentialDeploymentRequestDecoder.Logotype logotype : cred.getLogotypes ())
              {
                deployLogotype (logotype, pk.key_id);
              }

/*
            if (cred.isSigned ())
              {
                properties.append (" /SIGN");
              }
            String logotypes = "";
            String renewal = cred.getRenewalService () == null ? "" : " /REN (" + cred.getRenewalService ().getNotifyDaysBeforeExpiry () + ")";
            System.out.println ("ID=" +  cred.getID () + " Path=" + cred.getCertificatePath ().length + renewal + logotypes + properties.toString ());
*/
          }
        Connection conn = KeyUtil.getDatabaseConnection ();
        CallableStatement stmt = conn.prepareCall ("{call FinalizeProvisioningSP(?, ?, ?, ?, ?, ?)}");
        stmt.setString (1, credep_decoder.getServerSessionID ());
        stmt.setString (2, credep_decoder.getClientSessionID ());
        stmt.setInt (3, user_id);
        stmt.registerOutParameter (4, java.sql.Types.INTEGER);
        stmt.registerOutParameter (5, java.sql.Types.INTEGER);
        stmt.registerOutParameter (6, java.sql.Types.VARCHAR);
        stmt.execute ();
        int provision_id = stmt.getInt (4);
        int deleted_keys = stmt.getInt (5);
        String status = stmt.getString (6);
        stmt.close ();
        conn.close ();
        if (status != null)
          {
            throw new IOException (status);
          }
        if (deleted_keys > 0)
          {
            debugOutput ("Keys marked for deletion (" + deleted_keys + ") were deleted");
          }
        debugOutput ("Provisioning session #" + provision_id + " successfully terminated");
      }


    public void cleanupFailedProvisioning (KeyInitializationRequestDecoder keyopreq_decoder)
      {
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call CleanupProvisioningSP(?, ?, ?)}");
            stmt.setString (1, keyopreq_decoder.getServerSessionID ());
            stmt.setString (2, keyopreq_decoder.getClientSessionID ());
            stmt.setInt (3, user_id);
            stmt.execute ();
            stmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
          }
      }


    void deployPiggybackedSymmetricKey (CredentialDeploymentRequestDecoder.CertifiedPublicKey certified_public_key,
                                        CredentialDeploymentRequestDecoder decoder,
                                        int key_id)
    throws IOException, SQLException, GeneralSecurityException
      {
        byte[] private_key_handle = null;
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement ("SELECT PrivateKey FROM USERKEYS WHERE KeyID=?");
        pstmt.setInt (1, key_id);
        ResultSet rs = pstmt.executeQuery ();
        if (rs.next ())
          {
            private_key_handle = rs.getBytes (1);
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        if (private_key_handle == null)
          {
            throw new IOException ("Couldn't get PrivateKey for KeyID: " + key_id);
          }
        byte[] encrypted_symmetric_key = sks.provisionPiggybackedSymmetricKey
               (
                 certified_public_key.getPiggybackMACAlgorithm (),
                 certified_public_key.getEncryptedSymmetricKey (),
                 private_key_handle,
                 AsymEncryptionAlgorithms.RSA_PKCS_1,
                 certified_public_key.getSymmetricKeyEndorsedAlgorithms (),
                 certified_public_key.getSymmetricKeyMac (),
                 KeyAttestationUtil.createKA1Nonce (certified_public_key.getID (),
                                                    decoder.getClientSessionID (),
                                                    decoder.getServerSessionID ())

               );

        conn = KeyUtil.getDatabaseConnection ();
        pstmt = conn.prepareStatement ("UPDATE USERKEYS SET PrivateKey=NULL, SecretKey=?, SuppAlgs=? WHERE KeyID=?");
        pstmt.setBytes (1, encrypted_symmetric_key);
        String endorsed_alg_string = StringUtil.tokenList (certified_public_key.getSymmetricKeyEndorsedAlgorithms ());
        if (endorsed_alg_string.equals (KeyGen2URIs.ALGORITHMS.ANY))
          {
            endorsed_alg_string = null;
          }
        pstmt.setString (2, endorsed_alg_string);
        pstmt.setInt (3, key_id);
        pstmt.executeUpdate ();
        pstmt.close ();
        conn.close ();
        debugOutput ("Symmetric key deployed to KEY_ID=" + key_id);
      }


    private Object[] getInit (String sql, String type_uri) throws IOException, SQLException
      {
        Vector<Object> objects = new Vector<Object> ();
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement (sql);
        pstmt.setString (1, type_uri);
        ResultSet rs = pstmt.executeQuery ();
        Exception exception = null;
        while (exception == null && rs.next ())
          {
            try
              {
                objects.add (Class.forName (rs.getString (1)).newInstance ());
              }
            catch (ClassNotFoundException cnfe)
              {
                exception = cnfe;
              }
            catch (InstantiationException ie)
              {
                exception = ie;
              }
            catch (IllegalAccessException iae)
              {
                exception = iae;
              }
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        if (exception != null)
          {
            throw new WrappedException (exception);
          }
        return objects.toArray (new Object[0]);
      }


    void deployPropertyBag (CredentialDeploymentRequestDecoder.PropertyBag prop_bag,
                            KeyDescriptor key_descriptor) throws IOException, SQLException
      {
        for (Object instance : getInit ("SELECT PROPERTYBAGCONSUMERS.ImplClass FROM " +
                                               "PROPERTYBAGCONSUMERS, TYPEREGISTRY WHERE " +
                                               "PROPERTYBAGCONSUMERS.TypeID = TYPEREGISTRY.TypeID AND " +
                                               "TYPEREGISTRY.TypeURI = ?", prop_bag.getType ()))
          {
            PropertyBagConsumer pbc = ((PropertyBagConsumer) instance);
            pbc.parse (prop_bag, key_descriptor);
            debugOutput ("Property object of type '" + pbc.getName () + "' deployed to KEY_ID=" + key_descriptor.getKeyID ());
          }
        Connection conn = KeyUtil.getDatabaseConnection ();
        CallableStatement stmt = conn.prepareCall ("{call AddPropertyBagInstanceSP(?, ?, ?)}");
        stmt.registerOutParameter (3, java.sql.Types.INTEGER);
        stmt.setInt (1, key_descriptor.getKeyID ());
        stmt.setString (2, prop_bag.getType ());
        stmt.execute ();
        int prop_bag_id = stmt.getInt (3);
        stmt.close ();
        conn.close ();
        if (prop_bag_id == 0)
          {
            throw new IOException ("INSERT PROPERTYBAGS error");
          }
        conn = KeyUtil.getDatabaseConnection ();
        for (CredentialDeploymentRequestDecoder.Property prop : prop_bag.getProperties ())
          {
            PreparedStatement pstmt = conn.prepareStatement ("INSERT INTO PROPERTIES (PropBagID, PropName, PropValue, Writable) VALUES (?, ?, ?, ?)");
            pstmt.setInt (1, prop_bag_id);
            pstmt.setString (2, prop.getName ());
            pstmt.setString (3, prop.getValue ());
            pstmt.setBoolean (4, prop.isWritable ());
            pstmt.executeUpdate ();
            pstmt.close ();
          }
        conn.close ();
      }


    void deployExtension (CredentialDeploymentRequestDecoder.Extension extension,
                          KeyDescriptor key_descriptor) throws IOException, SQLException
      {
        for (Object instance : getInit ("SELECT EXTENSIONCONSUMERS.ImplClass FROM " +
                                               "EXTENSIONCONSUMERS, TYPEREGISTRY WHERE " +
                                               "EXTENSIONCONSUMERS.TypeID = TYPEREGISTRY.TypeID AND " +
                                               "TYPEREGISTRY.TypeURI = ?", extension.getType ()))
          {
            ExtensionConsumer ec = (ExtensionConsumer) instance;
            ec.parse (extension.getData (), key_descriptor);
            debugOutput ("Extension object of type '" + ec.getName () + "' deployed to KEY_ID=" + key_descriptor.getKeyID ());
          }
        Connection conn = KeyUtil.getDatabaseConnection ();
        CallableStatement stmt = conn.prepareCall ("{call AddExtensionInstanceSP(?, ?, ?, ?)}");
        stmt.registerOutParameter (4, java.sql.Types.INTEGER);
        stmt.setInt (1, key_descriptor.getKeyID ());
        stmt.setString (2, extension.getType ());
        stmt.setBytes (3, extension.getData ());
        stmt.execute ();
        int type_id = stmt.getInt (4);
        stmt.close ();
        conn.close ();
        if (type_id == 0)
          {
            throw new IOException ("INSERT EXTENSIONS error");
          }
      }


    void deployLogotype (CredentialDeploymentRequestDecoder.Logotype logotype, int key_id) throws IOException, SQLException
      {
        Connection conn = KeyUtil.getDatabaseConnection ();
        CallableStatement stmt = conn.prepareCall ("{call AddLogotypeInstanceSP(?, ?, ?, ?)}");
        stmt.setInt (1, key_id);
        stmt.setString (2, logotype.getType ());
        stmt.setBytes (3, logotype.getData ());
        stmt.setString (4, logotype.getMimeType ());
        stmt.execute ();
        stmt.close ();
        conn.close ();
        debugOutput ("Logotype object of type '" + logotype.getType () + "' deployed to KEY_ID=" + key_id);
      }


    int createPUKPolicy (int retry_limit,
                         PassphraseFormats format) throws IOException, SQLException
      {
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement ("INSERT INTO PUKPOLICIES (RetryLimit, PUKTryCount, Format) VALUES (?, ?, ?)",
                                                         PreparedStatement.RETURN_GENERATED_KEYS);
        pstmt.setInt (1, retry_limit);
        pstmt.setInt (2, retry_limit);
        pstmt.setInt (3, format.ordinal ());
        pstmt.executeUpdate ();
        int puk_policy_id = 0;
        ResultSet rs = pstmt.getGeneratedKeys ();
        if (rs.next ())
          {
            puk_policy_id = rs.getInt (1);
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        if (puk_policy_id == 0)
          {
            throw new IOException ("Couldn't get PUKPolicyID!");
          }
        debugOutput ("PUK policy object with PUK_ID=" + puk_policy_id + " created");
        return puk_policy_id;
      }


    int createPINPolicy (int retry_limit,
                         int min_length, int max_length,
                         PassphraseFormats format,
                         PINGrouping grouping,
                         PatternRestrictions[] pattern_restrictions,  // May be null
                         InputMethods input_methods,
                         boolean caching_support,
                         int puk_policy_id) throws IOException, SQLException
      {
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement ("INSERT INTO PINPOLICIES (" +
                                                                "RetryLimit, " +
                                                                "MinLength, " +
                                                                "MaxLength, " +
                                                                "Format, " +
                                                                "Grouping, " +
                                                                "PatternRestr, " +
                                                                "InputMeth, " +
                                                                "CachingSupp, " +
                                                                "PUKPolicyID) " +
                                                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                                         PreparedStatement.RETURN_GENERATED_KEYS);
        pstmt.setInt (1, retry_limit);
        pstmt.setInt (2, min_length);
        pstmt.setInt (3, max_length);
        pstmt.setInt (4, format.ordinal ());
        pstmt.setInt (5, grouping.ordinal ());
        byte[] pattrns = null;
        if (pattern_restrictions != null)
          {
            pattrns = new byte[pattern_restrictions.length + 1];
            pattrns[0] = (byte) (pattern_restrictions.length);
            int i = 0;
            for (PatternRestrictions pr : pattern_restrictions)
              {
                pattrns[++i] = (byte) (pr.ordinal ());
              }
          }
        pstmt.setBytes (6, pattrns);
        pstmt.setInt (7, input_methods.ordinal ());
        pstmt.setBoolean (8, caching_support);
        pstmt.setInt (9, puk_policy_id);
        pstmt.executeUpdate ();
        int pin_policy_id = 0;
        ResultSet rs = pstmt.getGeneratedKeys ();
        if (rs.next ())
          {
            pin_policy_id = rs.getInt (1);
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        if (pin_policy_id == 0)
          {
            throw new IOException ("Couldn't get PINPolicyID!");
          }
        return pin_policy_id;
      }


    int getDevicePUKPolicyID () throws IOException, SQLException
      {
        int puk_policy_id = 0;
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement ("SELECT PUKPolicyID FROM DEVICEDATA WHERE UserID=?");
        pstmt.setInt (1, user_id);
        ResultSet rs = pstmt.executeQuery ();
        if (rs.next ())
          {
            puk_policy_id = rs.getInt (1);
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        if (puk_policy_id == 0)
          {
            throw new IOException ("Couldn't get device PUKPolicyID!");
          }
        return puk_policy_id;
      }


    private void updatePresetValue (String get_format_sql, String update_value_sql,
                                    int primary_key_value, String value) throws IOException, SQLException
      {
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement (get_format_sql);
        pstmt.setInt (1, primary_key_value);
        ResultSet rs = pstmt.executeQuery ();
        PassphraseFormats format = null;
        if (rs.next ())
          {
            format = PassphraseFormats.values ()[rs.getInt (1)];
          }
        rs.close ();
        pstmt.close ();
        if (format == null)
          {
            conn.close ();
            throw new IOException ("Couldn't get format!");
          }
        pstmt = conn.prepareStatement (update_value_sql);
        pstmt.setBytes (1, KeyUtil.getPassphrase (value, format));
        pstmt.setInt (2, primary_key_value);
        pstmt.executeUpdate ();
        pstmt.close ();
        conn.close ();
      } 


    void updatePUKPolicy (int puk_policy_id, String value) throws IOException, SQLException
      {
        updatePresetValue ("SELECT Format FROM PUKPOLICIES WHERE PUKPolicyID=?",
                           "UPDATE PUKPOLICIES SET PUKValue=? WHERE PUKPolicyID=?",
                           puk_policy_id, value);
        debugOutput ("PUK policy object with PUK_ID=" + puk_policy_id + " value set to '" + value + "'");
      }


    void UpdatePINValue (int key_id, String value) throws IOException, SQLException
      {
        updatePresetValue ("SELECT Format FROM PINPOLICIES, USERKEYS WHERE USERKEYS.PINPolicyID=PINPOLICIES.PINPOlicyID AND USERKEYS.KeyID=?",
                           "UPDATE USERKEYS SET PINValue=? WHERE KeyID=?",
                           key_id, value);
        debugOutput ("PIN for key with KEY_ID=" + key_id + " value set to '" + value + "'");
      }


    public void storeDeviceCertificatePathAndKey (X509Certificate[] sorted_cert_path, PrivateKey private_key)
    throws IOException, SQLException, GeneralSecurityException
      {
        int puk_policy_id = createPUKPolicy (1000, PassphraseFormats.NUMERIC);
        updatePUKPolicy (puk_policy_id, "01234567890123456789");
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement ("INSERT INTO DEVICEDATA (UserID, CertPath, PrivateKey, PUKPolicyID) VALUES (?, ?, ?, ?)");
        pstmt.setInt (1, user_id);
        pstmt.setBytes (2, KeyUtil.createDBCertificatePath (sorted_cert_path));
        pstmt.setBytes (3, private_key.getEncoded ());
        pstmt.setInt (4, puk_policy_id);
        pstmt.executeUpdate ();
        pstmt.close ();
        conn.close ();
      }

  }
