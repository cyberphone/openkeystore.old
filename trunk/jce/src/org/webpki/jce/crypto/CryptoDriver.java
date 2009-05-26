package org.webpki.jce.crypto;

import java.io.IOException;

import java.math.BigInteger;

import java.util.LinkedHashMap;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;

import java.security.cert.X509Certificate;

import java.security.spec.X509EncodedKeySpec;

import org.webpki.util.WrappedException;

import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.MacAlgorithms;

import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyOperationRequestDecoder;

import org.webpki.jce.KeyUtil;

/**
 * This class is the bridge between the cryptographic high-level functions and the
 * Security&nbsp;Element.
 */
public class CryptoDriver
  {
    int user_id;

    VirtualSE virtual_se;

    public CryptoDriver (int user_id) throws IOException
      {
        this.user_id = user_id;
        try
          {
            byte[] encoded_private_key = null;
            byte[] encoded_certificate_path = null;
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("SELECT PrivateKey, CertPath FROM DEVICEDATA WHERE UserID=?");
            pstmt.setInt (1, user_id);
            ResultSet rs = pstmt.executeQuery ();
            if (rs.next ())
              {
                encoded_private_key = rs.getBytes (1);
                encoded_certificate_path = rs.getBytes (2);
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
            if (encoded_certificate_path == null)
              {
                throw new IOException  ("Couldn't get device CertPath!");
              }
            if (encoded_private_key == null)
              {
                throw new IOException  ("Couldn't get device PrivateKey!");
              }
            virtual_se = new VirtualSE (encoded_private_key, encoded_certificate_path);
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


    public static String[] getSupportedAlgorithms ()
      {
        return supported_algorithms.keySet ().toArray (new String[0]);
      }


    public static class KeyPair
      {
        private KeyPair () {}

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
      }


    public static class AttestedKeyPair extends KeyPair
      {
        private AttestedKeyPair () {}

        byte[] attest_signature;

        byte[] encrypted_private_key;

        byte[] wrapped_encryption_key;

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
    public static byte[] sealDevicePrivateKey (byte[] encoded_private_key) throws GeneralSecurityException
      {
        return VirtualSE.sealDevicePrivateKey (encoded_private_key);
      }

    public static String getDeviceName ()
      {
        return device_name;
      }

    public KeyPair generateKeyPair (KeyOperationRequestDecoder.KeyAlgorithmData key_alg,
                                    boolean exportable,
                                    KeyGen2KeyUsage key_usage)
    throws IOException
      {
        return generateAttestedKeyPair (key_alg,
                                        KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1,
                                        exportable,
                                        key_usage,
                                        new byte[32],
                                        null, null, null, null);
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
        AttestedKeyPair key_pair = new AttestedKeyPair ();
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
        return KeyUtil.restoreCertificatePathFromDB (singleArrayReturn (virtual_se.getPackedDeviceCertificatePath ()));
      }


    public static byte[] symmetricKeyHMAC (byte[] data,
                                           byte[] secret_key_handle,
                                           MacAlgorithms algorithm)
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

    public static byte[] privateKeyDigestSign (byte[] digest,
                                               byte[] private_key_handle,
                                               SignatureAlgorithms algorithm)
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


    public static byte[] symmetricKeyEncrypt (boolean encrypt_flag,
                                              byte[] data,
                                              byte[] secret_key_handle,
                                              SymEncryptionAlgorithms algorithm,
                                              byte[] optional_iv)
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

    public static byte[] privateKeyDecrypt (byte[] data,
                                            byte[] private_key_handle,
                                            AsymEncryptionAlgorithms algorithm)
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

    public static byte[] sealPrivateKey (PrivateKey private_key,
                                         boolean exportable,
                                         KeyGen2KeyUsage key_usage) throws IOException
      {
        return singleArrayReturn (VirtualSE.sealPrivateKey
          (
            new OutputBuffer ()
                .putArray (private_key.getEncoded ())
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

    public static byte[] sealSecretKey (byte[] secret_key,
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


    public static byte[] scramblePassword (byte[] password) throws IOException
      {
        return singleArrayReturn (VirtualSE.scramblePassword
          (
            new OutputBuffer ()
                .putArray (password)
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
    public static byte[] provisionPiggybackedSymmetricKey (String piggyback_mac_algorithm,
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
  }
