package org.webpki.sks.dbemulator;

import java.io.IOException;

import java.math.BigInteger;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.ServiceLoader;
import java.util.Vector;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.Signature;

import java.security.cert.X509Certificate;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.webpki.sks.DatabaseService;
import org.webpki.sks.KeyAuthorizationCallback;
import org.webpki.sks.Provisioning;
import org.webpki.sks.SecureKeyStore;
import org.webpki.sks.SetupProperties;
import org.webpki.util.ArrayUtil;
import org.webpki.util.WrappedException;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.ca.CA;
import org.webpki.ca.CertSpec;

import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.MacAlgorithms;


import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.KeyOperationRequestDecoder;
import org.webpki.keygen2.PassphraseFormats;


/**
 * This class is the bridge between the cryptographic high-level functions and the
 * Security&nbsp;Element.
 */
public class SKSEmulator implements SecureKeyStore, SetupProperties
  {
    int user_id;

    VirtualSE virtual_se;
    
    PrivateKey device_private_key = null;

    X509Certificate device_certificate = null;

    
    private static DatabaseService database_service = ServiceLoader.load (DatabaseService.class).iterator ().next ();
    
    private static final String USER_ID_PROPERTY = "UserID";

    private static class CASignature implements AsymKeySignerInterface
      {
        static final char[] password = "testing".toCharArray ();

        static final String key_alias = "mykey";

        KeyStore ks;

        CASignature () throws IOException, GeneralSecurityException
          {
            ks = KeyStore.getInstance ("JKS");
            ks.load (getClass ().getResourceAsStream ("deviceca.jks"), password);
          }

        public byte[] signData (byte[] data, SignatureAlgorithms sign_alg) throws IOException, GeneralSecurityException
          {
            Signature s = Signature.getInstance (sign_alg.getJCEName ());
            s.initSign ((PrivateKey) ks.getKey (key_alias, password));
            s.update (data);
            return s.sign ();
          }

        public PublicKey getPublicKey () throws IOException, GeneralSecurityException
          {
            return ks.getCertificate (key_alias).getPublicKey ();
          }

        X509Certificate getCertificate () throws IOException, GeneralSecurityException
          {
            return (X509Certificate) ks.getCertificate (key_alias);
          }
      }

    
    public SKSEmulator () throws IOException
      {
      }

    private static int se_buffer_length = 2000;

    static LinkedHashMap<String,Byte> supported_algorithms = new LinkedHashMap<String,Byte> ();

    static String device_name;

    static LinkedHashMap<Integer,Boolean> supported_rsa_sizes = new LinkedHashMap<Integer,Boolean> ();

    static LinkedHashMap<String,String> supported_ecc_curves = new LinkedHashMap<String,String> ();

    static
      {
        try
          {
            byte alg_id = (byte) 0xff;
            while (true)
              {
                InputBuffer input = new InputBuffer (VirtualSE.getNextAlgorithm (
                        new OutputBuffer ()
                           .putByte (alg_id)
                           .getBuffer ()));
                byte[] alg_uri = input.getArray ();
                if (alg_uri.length == 0)
                  {
                    break;
                  }
                alg_id = input.getByte ();
                supported_algorithms.put (new String (alg_uri, "UTF-8"), alg_id);
              }
            InputBuffer input = new InputBuffer (VirtualSE.getDeviceInformation ());
            device_name = new String (input.getArray (), "UTF-8");
            for (int rsa_caps = input.getByte (); rsa_caps > 0; rsa_caps--)
              {
                @SuppressWarnings("unused")
                int cap = input.getShort ();
              }
            for (int ecc_caps = input.getByte (); ecc_caps > 0; ecc_caps--)
              {
                @SuppressWarnings("unused")
                byte[] curve = input.getArray ();
              }
          }
        catch (Exception e)
          {
            System.out.println ("What?" + e.getMessage ());
          }
      }



    static byte[] createDBCertificatePath(X509Certificate[] sorted_cert_path)
        throws IOException, GeneralSecurityException
      {
        byte[] cert_path_bytes = new byte[] {(byte) sorted_cert_path.length };
        for (X509Certificate cert : sorted_cert_path)
          {
            byte[] cert_bytes = cert.getEncoded();
            cert_path_bytes = ArrayUtil.add(cert_path_bytes, ArrayUtil.add(
                new byte[] { (byte) (cert_bytes.length >>> 8),
                    (byte) (cert_bytes.length & 0xFF) }, cert_bytes));
          }
        return cert_path_bytes;
      }

    
    static X509Certificate[] restoreCertificatePathFromDB (byte[] encoded_cert_path) throws IOException
      {
        Vector<X509Certificate> certificates = new Vector<X509Certificate> ();
        int n = encoded_cert_path[0];
        int i = 1;
        while (n-- > 0)
          {
            int l = (encoded_cert_path[i++] << 8) + (encoded_cert_path[i++] & 0xFF);
            byte[] certificate = new byte[l];
            System.arraycopy (encoded_cert_path, i, certificate, 0, l);
            certificates.add (CertificateUtil.getCertificateFromBlob (certificate));
            i += l;
          }
        return certificates.toArray (new X509Certificate[0]);
      }


    public boolean isSupported (String algorithm)
      {
        return supported_algorithms.containsKey (algorithm);
      }


    private static class OutputBuffer
      {
        byte[] buffer;
        int length;

        OutputBuffer ()
          {
            buffer = new byte[se_buffer_length];
          }

        private OutputBuffer add (byte[] parameter) throws IOException
          {
            if (length + parameter.length >= se_buffer_length)
              {
                throw new IOException ("SE input buffer exceeded!");
              }
            System.arraycopy (parameter, 0, buffer, length, parameter.length);
            length += parameter.length;
            return this;
          }
 
        byte[] getBuffer ()
          {
            byte[] actual = new byte[length];
            System.arraycopy (buffer, 0, actual, 0, length);
            return actual;
          }

        OutputBuffer putByte (byte value) throws IOException
          {
            return add (new byte[] {(byte) 1, value});
          }

        OutputBuffer putByte (boolean value) throws IOException
          {
            return add (new byte[] {(byte) 1, value ? (byte)1 : (byte)0});
          }

        OutputBuffer putArray (byte[] array) throws IOException
          {
            if (array.length >= 0xff)
              {
                add (new byte[] {(byte) 0xff, (byte) ((array.length >> 8) & 0xff), (byte) (array.length & 0xff)});
              }
            else
              {
                add (new byte[] {(byte) array.length});
              }
           return add (array);
          }


        OutputBuffer putShort (int value) throws IOException
          {
            return add (new byte[] {(byte) 0x02, (byte) ((value >> 8) & 0xff), (byte) (value & 0xff)});
          }


        OutputBuffer putBigInteger (BigInteger big) throws IOException
          {
            if (big == null)
              {
                return add (new byte[]{0});
              }
            return putArray (big.toByteArray ());
          }
     }


    private static class InputBuffer
      {
        byte[] buffer;
        int curr_pos;
        int tag_size;

        InputBuffer (byte[] buffer) throws IOException
          {
            this.buffer = buffer;
            if (buffer.length > 0 && buffer[0] == 0)
              {
                curr_pos++;
              }
            else
              {
                String msg = "Couldn't get SE error message!";
                if (buffer.length > 3)
                  {
                    int length = (buffer[1] << 8) + (buffer[2] & 0xff);
                    if (length > 0 && length < 1000)
                    try
                      {
                        byte[] err = new byte[length];
                        System.arraycopy (buffer, 3, err, 0, length);
                        msg = new String (err, "UTF-8");
                      }
                    catch (IOException iox)
                      {
                      }
                  }
                throw new IOException ("SE reported: " + msg);
              }
          }

        private void check (int position) throws IOException
          {
            if (position >= buffer.length)
              {
                throw new IOException ("Input buffer underrun");
              }
          }

        private int getLength () throws IOException 
          {
            check (curr_pos);
            tag_size = 1;
            int length = buffer[curr_pos] & 0xff;
            if (length == 0xff)
              {
                check (curr_pos + 2);
                length = (buffer[curr_pos + 1] << 8) | (buffer[curr_pos + 2] & 0xFF);
                tag_size = 3;
              }
            return length;
          }

        private byte[] getItem (int length) throws IOException
          {
            check (curr_pos + tag_size + length);
            byte[] result = new byte[length];
            System.arraycopy (buffer, curr_pos + tag_size, result, 0, length);
            curr_pos += tag_size + length;
            return result;
          }

        private byte[] getData (int length_constraint) throws IOException
          {
            int length = getLength ();
            if (length_constraint != length)
              {
                throw new IOException ("Tag length error");
              }
            return getItem (length);
          }
        
        private byte[] getData () throws IOException
          {
            return getItem (getLength ());
          }
        
        int getShort () throws IOException
          {
            byte[] b = getData (2);
            return (b[0] * 8) + (b[1] & 0xff);
          }

        byte getByte () throws IOException
          {
            return getData (1)[0];
          }

        byte[] getArray () throws IOException
          {
            return getData ();
          }
      }


    private static byte[] singleArrayReturn (byte[] return_block) throws IOException
      {
        return new InputBuffer (return_block).getArray ();
      }


    static byte getSEAlgorithmIDFromURI (String uri) throws IOException
      {
        Byte alg_id = supported_algorithms.get (uri);
        if (alg_id == null)
          {
            throw new IOException ("Unsupported algorithm: " + uri);
          }
        return alg_id;
      }


    public String[] getSupportedAlgorithms ()
      {
        return supported_algorithms.keySet ().toArray (new String[0]);
      }


    private class LocalAttestedKeyPair implements SecureKeyStore.AttestedKeyPair   
      {
        private LocalAttestedKeyPair () {}

        byte[] attest_signature;

        byte[] encrypted_private_key;

        byte[] wrapped_encryption_key;

        PublicKey public_key;

        byte[] private_key_handle;


        public PublicKey getPublicKey ()
          {
            return public_key;
          }

        public byte[] getPrivateKeyHandle ()
          {
            return private_key_handle;
          }

        public byte[] getAttestSignature ()
          {
            return attest_signature;
          }

        public byte[] getEncryptedPrivateKey ()
          {
            return encrypted_private_key;
          }

        public byte[] getWrappedEncryptionKey ()
          {
            return wrapped_encryption_key;
          }
      }

    private static PublicKey getPublicKey (byte[] encoded)
      {
        try
          {
            return KeyFactory.getInstance ("RSA").generatePublic (new X509EncodedKeySpec (encoded));
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
      }

   // Note: This is just a "special" outside of the SE design.
    public byte[] sealDevicePrivateKey (byte[] encoded_private_key) throws GeneralSecurityException
      {
        return VirtualSE.sealDevicePrivateKey (encoded_private_key);
      }

    public String getDeviceName ()
      {
        return device_name;
      }


    public AttestedKeyPair generateAttestedKeyPair (KeyOperationRequestDecoder.KeyAlgorithmData key_alg,
                                                    String attestation_algorithm,
                                                    boolean exportable,
                                                    KeyGen2KeyUsage key_usage,
                                                    byte[] nonce,
                                                    byte[] opt_archival_public_key,
                                                    String private_key_format_uri,
                                                    SymEncryptionAlgorithms encrytion_algorithm,
                                                    AsymEncryptionAlgorithms key_wrap_algorithm)
    throws IOException
      {
        OutputBuffer input = new OutputBuffer ();
        if (key_alg instanceof KeyOperationRequestDecoder.RSA)
          {
            input.putByte ((byte)0)
                 .putShort (((KeyOperationRequestDecoder.RSA) key_alg).getKeySize ())
                 .putBigInteger (((KeyOperationRequestDecoder.RSA) key_alg).getFixedExponent ());
          }
        else
          {
            input.putByte ((byte)1)
                 .putArray (((KeyOperationRequestDecoder.ECC) key_alg).getNamedCurve ().getOID ().getBytes ("UTF-8"));
          }
        input.putByte (getSEAlgorithmIDFromURI (attestation_algorithm))
             .putByte (exportable)
             .putByte ((byte)key_usage.ordinal ())
             .putArray (nonce);
        if (opt_archival_public_key != null)
          {
            input.putArray (opt_archival_public_key);
            input.putByte (getSEAlgorithmIDFromURI (private_key_format_uri));
            input.putByte (getSEAlgorithmIDFromURI (encrytion_algorithm.getURI ()));
            input.putByte (getSEAlgorithmIDFromURI (key_wrap_algorithm.getURI ()));
          }
        InputBuffer result =
             new InputBuffer (virtual_se.generateAttestedKeyPair (input.getBuffer ()));
        LocalAttestedKeyPair key_pair = new LocalAttestedKeyPair ();
        key_pair.public_key = getPublicKey (result.getArray ());
        key_pair.private_key_handle = result.getArray ();
        key_pair.attest_signature = result.getArray ();
        if (opt_archival_public_key != null)
          {
            key_pair.encrypted_private_key = result.getArray ();
            key_pair.wrapped_encryption_key = result.getArray ();
          }
        return key_pair;
      }


    public byte[] deviceKeyDecrypt (byte[] data, AsymEncryptionAlgorithms algorithm) throws IOException
      {
        return singleArrayReturn (virtual_se.deviceKeyDecrypt
          (
            new OutputBuffer ()
                .putArray (data)
                .putByte (getSEAlgorithmIDFromURI (algorithm.getURI ()))
                .getBuffer ()
          ));
      }
  

    public byte[] deviceKeyDigestSign (byte[] digest, SignatureAlgorithms algorithm) throws IOException
      {
        return singleArrayReturn (virtual_se.deviceKeyDigestSign
          (
            new OutputBuffer ()
                .putArray (digest)
                .putByte (getSEAlgorithmIDFromURI (algorithm.getURI ()))
                .getBuffer ()
          ));
      }


    public X509Certificate[] getDeviceCertificatePath () throws IOException
      {
        return new X509Certificate[]{device_certificate};
      }


    public byte[] symmetricKeyHMAC (byte[] data,
                                    byte[] secret_key_handle,
                                    MacAlgorithms algorithm,
                                    byte[] optional_pin,
                                    KeyAuthorizationCallback key_auth_callback)
    throws IOException
      {
        return singleArrayReturn (VirtualSE.symmetricKeyHMAC
          (
            new OutputBuffer ()
                .putArray (data)
                .putArray (secret_key_handle)
                .putByte (getSEAlgorithmIDFromURI (algorithm.getURI ()))
                .getBuffer ()
          ));
      }

    public byte[] privateKeyDigestSign (byte[] digest,
                                        byte[] private_key_handle,
                                        SignatureAlgorithms algorithm,
                                        byte[] optional_pin)
    throws IOException
      {
        return singleArrayReturn (VirtualSE.privateKeyDigestSign
          (
            new OutputBuffer ()
                .putArray (digest)
                .putArray (private_key_handle)
                .putByte (getSEAlgorithmIDFromURI (algorithm.getURI ()))
                .getBuffer ()
          ));
      }


    public byte[] symmetricKeyEncrypt (boolean encrypt_flag,
                                       byte[] data,
                                       byte[] secret_key_handle,
                                       SymEncryptionAlgorithms algorithm,
                                       byte[] optional_iv,
                                       byte[] optional_pin)
    throws IOException
      {
        return singleArrayReturn (VirtualSE.symmetricKeyEncrypt
          (
            new OutputBuffer ()
                .putByte (encrypt_flag)
                .putArray (data)
                .putArray (secret_key_handle)
                .putByte (getSEAlgorithmIDFromURI (algorithm.getURI ()))
                .putArray (optional_iv == null ? new byte[0] : optional_iv)
                .getBuffer ()
          ));
      }

    public byte[] privateKeyDecrypt (byte[] data,
                                     byte[] private_key_handle,
                                     AsymEncryptionAlgorithms algorithm,
                                     byte[] optional_pin)
    throws IOException
      {
        return singleArrayReturn (VirtualSE.privateKeyDecrypt
          (
            new OutputBuffer ()
                .putArray (data)
                .putArray (private_key_handle)
                .putByte (getSEAlgorithmIDFromURI (algorithm.getURI ()))
                .getBuffer ()
          ));
      }

    public byte[] sealPrivateKey (PrivateKey device_private_key,
                                  boolean exportable,
                                  KeyGen2KeyUsage key_usage) throws IOException
      {
        return singleArrayReturn (VirtualSE.sealPrivateKey
          (
            new OutputBuffer ()
                .putArray (device_private_key.getEncoded ())
                .putByte (exportable)
                .putByte ((byte)key_usage.ordinal ())
                .getBuffer ()
          ));
      }

    private static byte[] getAlgorithmsFromURIs (String[] algorithm_uris)
    throws IOException
      {
        byte[] algorithms_local = new byte[algorithm_uris.length];
        int i = 0;
        for (String alg_uri : algorithm_uris)
          {
            algorithms_local[i++] = getSEAlgorithmIDFromURI (alg_uri);
          }
        return algorithms_local;
      }

    public byte[] sealSecretKey (byte[] secret_key,
                                 boolean exportable,
                                 String[] endorsed_algorithms) throws IOException
      {
        return singleArrayReturn (VirtualSE.sealSecretKey
          (
            new OutputBuffer ()
                .putArray (secret_key)
                .putByte (exportable)
                .putArray (getAlgorithmsFromURIs (endorsed_algorithms))
                .getBuffer ()
           ));
      }


    /**
     * Provisions a KeyGen2 "piggybacked" symmetric key. Below is an example:      
     * <pre>  &lt;PiggybackedSymmetricKey EndorsedAlgorithms="http://www.w3.org/2000/09/xmldsig#hmac-sha1"
                           MAC="14z1RfdoVeDqYfSviPWZD4c2AL4="&gt;
      &lt;xenc:EncryptedKey&gt;
          &lt;xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/&gt;
          &lt;xenc:CipherData&gt;
              &lt;xenc:CipherValue&gt;VA2TbKUq...HQk9HoOIwCeSs=&lt;/xenc:CipherValue&gt;
          &lt;/xenc:CipherData&gt;
      &lt;/xenc:EncryptedKey&gt;
  &lt;/PiggybackedSymmetricKey&gt;</pre>
     * @param encrypted_symmetric_key The encrypted data as featured in the <code>"CipherValue"</code> element.
     * @param private_key_handle The sealed private key associated with the public key
     * certificate holding the <code>"PiggybackedSymmetricKey"</code> element.
     * @param encryption_algorithm The XML encryption <code>"Algorithm"</code>.
     * @param endorsed_algorithms The <code>"EndorsedAlgorithms"</code> as declared in the <code>"PiggybackedSymmetricKey"</code> element
     * where the algorithm URIs have been sorted in alphabetical order.
     * @param declared_mac The <code>"MAC"</code> as declared in the <code>"PiggybackedSymmetricKey"</code> element.
     * The <code>declared_mac</code> must match the HMAC-SHA1 value of the UTF-8 encoded
     * string of <code>"EndorsedAlgorithms"</code> with the whitespace removed, where the algorithm URIs
     * have been sorted in lexical order and where each algorithm URI has been appended by a '\0' character.
     * The decrypted symmetric key is used as HMAC input key.
     * @return A sealed symmetric key.
     */
    public byte[] provisionPiggybackedSymmetricKey (String piggyback_mac_algorithm,
                                                    byte[] encrypted_symmetric_key,
                                                    byte[] private_key_handle,
                                                    AsymEncryptionAlgorithms encryption_algorithm,
                                                    String[] endorsed_algorithms,
                                                    byte[] declared_mac,
                                                    byte[] nonce)
    throws IOException
      {
        return singleArrayReturn (VirtualSE.provisionPiggybackedSymmetricKey
          (
            new OutputBuffer ()
                .putByte (getSEAlgorithmIDFromURI (piggyback_mac_algorithm))
                .putByte (getSEAlgorithmIDFromURI (encryption_algorithm.getURI ()))
                .putArray (encrypted_symmetric_key)
                .putArray (private_key_handle)
                .putArray (getAlgorithmsFromURIs (endorsed_algorithms))
                .putArray (declared_mac)
                .putArray (nonce)
                .getBuffer ()
           ));
      }


    @Override
    public String[] getProperties()
      {
        return new String[]{USER_ID_PROPERTY};
      }


    @Override
    public void init() throws IOException
      {
        if (user_id < 1)
          {
            throw new IOException ("Property " + USER_ID_PROPERTY + " was not set!");
          }
        try
          {
            Connection conn = database_service.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("SELECT PrivateKey, CertPath FROM DEVICEDATA WHERE UserID=?");
            pstmt.setInt (1, user_id);
            ResultSet rs = pstmt.executeQuery ();
            if (rs.next ())
              {
                PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (rs.getBytes (1));
                device_private_key = KeyFactory.getInstance ("RSA").generatePrivate (key_spec);
                device_certificate = restoreCertificatePathFromDB (rs.getBytes (2))[0];
              }
            rs.close ();
            pstmt.close ();
            if (device_certificate == null)
              {
                pstmt = conn.prepareStatement ("INSERT INTO PUKPOLICIES (RetryLimit, PUKTryCount, Format, PUKValue) VALUES (?,?,?,?)",
                                               PreparedStatement.RETURN_GENERATED_KEYS);
                pstmt.setInt (1, 3);
                pstmt.setInt (2, 3);
                pstmt.setInt (3, PassphraseFormats.NUMERIC.ordinal ());
                pstmt.setString (4, "01234567890123456789");
                pstmt.executeUpdate ();
                int puk_policy_id = 0;
                rs = pstmt.getGeneratedKeys ();
                if (rs.next ())
                  {
                    puk_policy_id = rs.getInt (1);
                  }
                rs.close ();
                pstmt.close ();
                if (puk_policy_id == 0)
                  {
                    throw new IOException ("Couldn't get PUKPolicyID!");
                  }
                CertSpec cert_spec = new CertSpec ();
                cert_spec.setEndEntityConstraint ();
                cert_spec.setSubject ("CN=Device Type 1AK4,serialNumber=" + user_id + ",dc=webpki,dc=org");

                GregorianCalendar start = new GregorianCalendar ();
                GregorianCalendar end = (GregorianCalendar) start.clone ();
                end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);

                KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
                kpg.initialize (2048);
                KeyPair key_pair = kpg.generateKeyPair ();

                CASignature ca_sign = new CASignature ();
                device_certificate = 
                    new CA ().createCert (cert_spec,
                                          DistinguishedName.subjectDN (ca_sign.getCertificate ()),
                                          new BigInteger (String.valueOf (new Date ().getTime ())),
                                          start.getTime (), end.getTime (), 
                                          SignatureAlgorithms.RSA_SHA1,
                                          ca_sign,
                                          key_pair.getPublic ());
                device_private_key = key_pair.getPrivate ();
                pstmt = conn.prepareStatement ("INSERT INTO DEVICEDATA (UserID, CertPath, PrivateKey, PUKPolicyID) VALUES (?, ?, ?, ?)");
                pstmt.setInt (1, user_id);
                pstmt.setBytes (2, createDBCertificatePath (new X509Certificate[]{device_certificate}));
                pstmt.setBytes (3, device_private_key.getEncoded ());
                pstmt.setInt (4, puk_policy_id);
                pstmt.executeUpdate ();
                pstmt.close ();
              }
            conn.close ();
            virtual_se = new VirtualSE ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
      }


    @Override
    public byte[] privateKeyDecrypt(byte[] data, int key_id,
        AsymEncryptionAlgorithms algorithm, byte[] optional_pin,
        KeyAuthorizationCallback key_auth_callback) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public byte[] privateKeyDigestSign(byte[] digest, int key_id,
        SignatureAlgorithms algorithm, byte[] optional_pin,
        KeyAuthorizationCallback key_auth_callback) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public void setProperty (String name, String value) throws IOException
      {
        if (name.equalsIgnoreCase (USER_ID_PROPERTY))
          {
            user_id = Integer.parseInt (value);
          }
        else
          {
            throw new IOException ("Unknown property: " + name); 
          }
      }


    @Override
    public byte[] symmetricKeyEncrypt(boolean encrypt_flag, byte[] data,
        int key_id, SymEncryptionAlgorithms algorithm, byte[] optional_iv,
        byte[] optional_pin, KeyAuthorizationCallback key_auth_callback)
        throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public byte[] symmetricKeyHMAC(byte[] data, int key_id,
        MacAlgorithms algorithm, byte[] optional_pin,
        KeyAuthorizationCallback key_auth_callback) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }
 

  }
