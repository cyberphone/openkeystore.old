package org.webpki.jce.crypto;

import java.io.IOException;

import java.util.Vector;

import java.math.BigInteger;

import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.KeyPair;

import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Mac;
import javax.crypto.Cipher;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.interfaces.RSAKey;

import org.webpki.keygen2.KeyGen2URIs;


/**
 * A "Virtual" SE (Security&nbsp;Element).
 * &nbsp;<a name="VSE">This class emulates a simple SE where keys
 * are stored <i>externally</i>, but encrypted by an AES "master" key inside of the SE.&nbsp;
 * The master key is also responsible for verifying the integrity of supplied key objects which is
 * done through HMAC signatures.&nbsp;
 * In addition to the "master" key,
 * there is a device certificate with a corresponding private key,
 * primarily intended for &quot;bootstrapping&quot; user-credentials by <i>attesting the
 * authenticity of generated keys</i>, <i>preserving message integrity</i>,
 * and <i>providing encryption
 * for downloaded secrets</i>.&nbsp;
 * Using the KeyGen2 provisioning protocol, the latter is limited to PUKs and preset
 * PINs.&nbsp;
 * Below is a picture of the SE architecture:<p>
 * <center><img src="javadoc-tpm-picture.png" title="Security Elements rock!"></center><p>
 * Access control including PIN error counting is not a part of this design which is
 * intended to provide protection from key theft, but not from key "misuse".&nbsp;
 * The latter is intended to be catered for by a trusted layer or virtual machine
 * in the operating system itself,
 * which also includes a trusted GUI for PIN input etc.&nbsp;
 * An unusual feature of this SE design is that supported algorithm IDs are not
 * meant to be supplied in the traditional ".h" file, but are discoverable by the SE
 * interface software.&nbsp;
 * The same applies to the capabilities in terms of key sizes and technologies.&nbsp;
 * The described SE scheme is designed to consume as little RAM as is close to theoretically possible,
 * and it is also entirely stateless.  Algorithm support is as follows:
 * <style type="text/css">
 * .dbTR {font-weight:normal;font-size:10pt;font-family:verdana,arial;border-width:1px 1px 1px 0;border-style:solid;border-color:black;padding:4px}
 * .dbTL {font-weight:normal;font-size:10pt;font-family:verdana,arial;border-width:1px 1px 1px 1px;border-style:solid;border-color:black;padding:4px}
 * .dbNL {font-weight:normal;font-size:10pt;font-family:verdana,arial;border-width:0 1px 1px 1px;border-style:solid;border-color:black;padding:4px} 
 * .dbNR {font-weight:normal;font-size:10pt;font-family:verdana,arial;border-width:0 1px 1px 0;border-style:solid;border-color:black;padding:4px}
 * .dbLN {font-weight:normal;font-size:10pt;font-family:verdana,arial;border-width:0 1px 1px 1px;border-style:solid;border-color:black;padding:4px}
 * </style><p>
 * <table cellpadding="0" cellspacing="0">
 * <tr>
 * <td class="dbTL" align="center" style="background-color:#E0E0E0">Asymmetric Key Encryption</td>
 * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
 * 
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmlenc#rsa-1_5</td>
 * </tr>
 * 
 * <tr><td colspan="2" background="hshaddow.gif" height="2"></td></tr>
 *
 * <tr><td colspan="2">&nbsp;</td></tr>
 * <tr>
 * <td class="dbTL" align="center" style="background-color:#E0E0E0">Asymmetric Key Signatures</td>
 * <td rowspan="9" background="vshaddow.gif" width="2"></td></tr>
 * 
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2000/09/xmldsig#rsa-sha1</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#rsa-sha256</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#rsa-sha384</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#rsa-sha512</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512</td>
 * </tr>
 * 
 * <tr><td colspan="2" background="hshaddow.gif" height="2"></td></tr>
 *
 * <tr><td colspan="2">&nbsp;</td></tr>
 * <tr>
 * <td class="dbTL" align="center" style="background-color:#E0E0E0">HMAC Functions</td>
 * <td rowspan="6" background="vshaddow.gif" width="2"></td></tr>
 * 
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#hmac-md5</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2000/09/xmldsig#hmac-sha1</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#hmac-sha256</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#hmac-sha384</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmldsig-more#hmac-sha512</td>
 * </tr>
 *
 * <tr><td colspan="2" background="hshaddow.gif" height="2"></td></tr>
 *
 * <tr><td colspan="2">&nbsp;</td></tr>
 * <tr>
 * <td class="dbTL" align="center" style="background-color:#E0E0E0">Symmetric Key Encryption &amp; Decryption</td>
 * <td rowspan="5" background="vshaddow.gif" width="2"></td></tr>
 * 
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmlenc#aes128-cbc</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmlenc#aes256-cbc</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmlenc#kw-aes128</td>
 * </tr>
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://www.w3.org/2001/04/xmlenc#kw-aes256</td>
 * </tr>
 *
 * <tr><td colspan="2" background="hshaddow.gif" height="2"></td></tr>
 *
 * <tr><td colspan="2">&nbsp;</td></tr>
 * <tr>
 * <td class="dbTL" align="center" style="background-color:#E0E0E0">Private Key Formats</td>
 * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
 * 
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://xmlns.webpki.org/keygen2/1.0#format.pkcs8</td>
 * </tr>
 *
 * <tr><td colspan="2" background="hshaddow.gif" height="2"></td></tr>

 * <tr><td colspan="2">&nbsp;</td></tr>
 * <tr>
 * <td class="dbTL" align="center" style="background-color:#E0E0E0">KeyGen2 Specific</td>
 * <td rowspan="3" background="vshaddow.gif" width="2"></td></tr>
 * 
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://xmlns.webpki.org/keygen2/1.0#algorithm.key-attestation-1</td>
 * </tr>
 *
 * <tr bgcolor="ivory">
 * <td align="left" class="dbNL">http://xmlns.webpki.org/keygen2/1.0#algorithm.mac-piggyback-1</td>
 * </tr>
 *
 * <tr><td colspan="2" background="hshaddow.gif" height="2"></td></tr>
 *
 * </table><p>
 * Not shown in the method descriptions is the error-handling because it is generic: A successful method
 * return is prepended with a byte having the value 0, while an error is indicated by the value 1, followed
 * by a two-byte length specifier and an UTF-8 encoded error message.
 */
public class VirtualSE
  {
    static final String DEVICE_NAME = "Virtual Security Element V0.1, WebPKI.org";

    static final int IV_REQUIRED = 1;

    static final int IS_KEY_WRAPPER = 2;

    static final int KEY_16 = 4;

    static final int KEY_32 = 8;

    static final int RAW_RSA = 16;

    static final byte USER_SECRET_KEY               = (byte) 0x00;
    static final byte USER_PRIVATE_KEY              = (byte) 0x01;
    static final byte DEVICE_PRIVATE_KEY            = (byte) 0x02;

    enum ECCCapabilities
      {
        P_192   ("1.2.840.10045.3.1.1", "P-192"),
        P_256   ("1.2.840.10045.3.1.7", "P-256"),
        P_384   ("1.3.132.0.34",        "P-384");

        private final String oid;       // As expressed in ASN.1 messages
        private final String jcename;   // As expressed for JCE

        private ECCCapabilities (String oid, String jcename)
          {
            this.oid = oid;
            this.jcename = jcename;
          }


        private byte[] getOID () throws Exception
          {
            return oid.getBytes ("UTF-8");
          }


        private static String getJCEName (byte[] oid) throws Exception
          {
            for (ECCCapabilities alg : values ())
              {
                if (compareArrays (oid, alg.getOID ()))
                  {
                    return alg.jcename;
                  }
              }
            throw new Exception ("Unknown curve");
          }

      }

    private static class SupportedAlgorithms
      {

        byte[] algorithm_uri;

        String jcename;

        int alg_params;

        byte[] digest_info;

      }

    private static SupportedAlgorithms[] supported_algorithms;

    private static Vector<SupportedAlgorithms> temp_s_a = new Vector<SupportedAlgorithms> ();

    private static SupportedAlgorithms init (String uri, String jcename, int alg_params)
      {
        try
          {
            SupportedAlgorithms sa = new SupportedAlgorithms ();
            sa.algorithm_uri = uri.getBytes ("UTF-8");
            sa.jcename = jcename;
            sa.alg_params = alg_params;
            temp_s_a.add (sa);
            return sa;
          }
        catch (IOException iox)
          {
            return null;
          }
      }

    private static SupportedAlgorithms init (String uri, String jcename)
      {
        return init (uri, jcename, 0);
      }

    static final byte[] DIGEST_INFO_SHA1   = new byte[] {(byte)0x30, (byte)0x21, (byte)0x30, (byte)0x09, (byte)0x06,
                                                         (byte)0x05, (byte)0x2b, (byte)0x0e, (byte)0x03, (byte)0x02,
                                                         (byte)0x1a, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x14};

    static final byte[] DIGEST_INFO_SHA256 = new byte[] {(byte)0x30, (byte)0x31, (byte)0x30, (byte)0x0d, (byte)0x06,
                                                         (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01,
                                                         (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x01,
                                                         (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x20};

    static final byte[] DIGEST_INFO_SHA384 = new byte[] {(byte)0x30, (byte)0x41, (byte)0x30, (byte)0x0d, (byte)0x06,
                                                         (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01,
                                                         (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x02,
                                                         (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x30};

    static final byte[] DIGEST_INFO_SHA512 = new byte[] {(byte)0x30, (byte)0x51, (byte)0x30, (byte)0x0d, (byte)0x06,
                                                         (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01,
                                                         (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x03,
                                                         (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x40};
  
    static
      {
        // Any symmetric
        init (KeyGen2URIs.ALGORITHMS.ANY, "N/A");

        // HMAC
        init ("http://www.w3.org/2001/04/xmldsig-more#hmac-md5",    "HmacMD5");
        init ("http://www.w3.org/2000/09/xmldsig#hmac-sha1",        "HmacSHA1");
        init ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256");
        init ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HmacSHA384");
        init ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HmacSHA512");

        // Symmetric Key Encryption & Decryption
        init ("http://www.w3.org/2001/04/xmlenc#aes128-cbc",        "AES/CBC/PKCS5Padding", IV_REQUIRED | KEY_16);
        init ("http://www.w3.org/2001/04/xmlenc#aes256-cbc",        "AES/CBC/PKCS5Padding", IV_REQUIRED | KEY_32);
        init ("http://www.w3.org/2001/04/xmlenc#kw-aes128",         "AESWrap",              IS_KEY_WRAPPER | KEY_16);
        init ("http://www.w3.org/2001/04/xmlenc#kw-aes256",         "AESWrap",              IS_KEY_WRAPPER | KEY_32);
        init ("internal:AES/ECB/NoPadding",                         "AES/ECB/NoPadding");
        init ("internal:AES/ECB/PKCS5Padding",                      "AES/ECB/PKCS5Padding");
        init ("internal:AES/CBC/NoPadding",                         "AES/CBC/NoPadding",    IV_REQUIRED);
        init ("internal:AES/CBC/PKCS5Padding",                      "AES/CBC/PKCS5Padding", IV_REQUIRED);

        // Asymmetric Key Encryption & Decryption
        init ("http://www.w3.org/2001/04/xmlenc#rsa-1_5",           "RSA/ECB/PKCS1Padding");
        init ("internal:RSA/ECB/NoPadding",                         "RSA/ECB/NoPadding",    RAW_RSA);

        // Asymmetric Key Signatures
        init ("http://www.w3.org/2000/09/xmldsig#rsa-sha1",         "SHA1withRSA").digest_info = DIGEST_INFO_SHA1;
        init ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",  "SHA256withRSA").digest_info = DIGEST_INFO_SHA256;
        init ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",  "SHA384withRSA").digest_info = DIGEST_INFO_SHA384;
        init ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",  "SHA512withRSA").digest_info = DIGEST_INFO_SHA512;
        init ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",   "SHA1withECDSA").digest_info = DIGEST_INFO_SHA1;
        init ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "SHA256withECDSA").digest_info = DIGEST_INFO_SHA256;
        init ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "SHA384withECDSA").digest_info = DIGEST_INFO_SHA384;
        init ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "SHA512withECDSA").digest_info = DIGEST_INFO_SHA512;

        // Private Key Formats
        init ("http://xmlns.webpki.org/keygen2/1.0#format.pkcs8", "N/A");

        // KeyGen2 Specific
        init ("http://xmlns.webpki.org/keygen2/1.0#algorithm.key-attestation-1", "N/A");
        init ("http://xmlns.webpki.org/keygen2/1.0#algorithm.mac-piggyback-1", "N/A");

        supported_algorithms = temp_s_a.toArray (new SupportedAlgorithms[0]);
      }


    static final String SHA1               = "SHA-1";

    static final String SHA256             = "SHA-256";

    static final String HMAC_SHA1          = "HmacSHA1";

    static final String HMAC_SHA256        = "HmacSHA256";

    static final String UNFORMATTED_RSA    = "RSA/ECB/NoPadding";

    static final String RSA_PKCS1          = "RSA/ECB/PKCS1Padding";

    static final String AES_CBC_PKCS5      = "AES/CBC/PKCS5Padding";

    static final byte[] PS_PKCS1_DIAS      = new byte[] {(byte)0x00, (byte)'D',  (byte)'I',  (byte)'A',  (byte)'S'};

    static final byte[] PS_PKCS1_STD       = new byte[] {(byte)0x00};

    private static final SecretKeySpec master_encryption_key = 
             new SecretKeySpec (new byte[]{34,95,28,93,-77,22,9,87,-88,92,1,-30,25,32,12,56}, "AES");

    private static final SecretKeySpec password_encryption_key = 
             new SecretKeySpec (new byte[]{34,5,28,93,-77,22,9,87,-8,92,1,30,25,-3,12,56}, "AES");


    private static final String KEY_ENCRYPTION_MODE      = "AES/CBC/PKCS5Padding";

    private static final String PASSWORD_ENCRYPTION_MODE = "AES/ECB/PKCS5Padding";


    private PrivateKey device_private_key;

    private byte[] packed_device_certificates;

    private static int se_buffer_length = 4000;


    VirtualSE (byte[] device_private_key_handle, byte[] packed_device_certificates) throws GeneralSecurityException
      {
        this.device_private_key = unsealPrivateKey (device_private_key_handle, DEVICE_PRIVATE_KEY);
        this.packed_device_certificates = packed_device_certificates;
      }


    private static byte[] addArrays (byte[] a, byte[] b)
      {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy (a, 0, r, 0, a.length);
        System.arraycopy (b, 0, r, a.length, b.length);
        return r;
      }
    

    private static boolean compareArrays (byte[] a, byte[] b)
      {
        if (a.length != b.length)
          {
            return false;
          }
        for (int i = 0; i < a.length; i++)
          {
            if (a[i] != b[i])
              {
                return false;
              }
          }
        return true;
      }


    private static class InputBuffer
      {
        byte[] buffer;
        int curr_pos;
        int tag_size;

        InputBuffer (byte[] buffer)
          {
            this.buffer = buffer;
          }

        private void check (int total) throws GeneralSecurityException
          {
            if (total > buffer.length)
              {
                throw new GeneralSecurityException ("Input buffer underrun");
              }
          }

        private int getLength () throws GeneralSecurityException 
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

        private byte[] getItem (int length) throws GeneralSecurityException
          {
            check (curr_pos + tag_size + length);
            byte[] result = new byte[length];
            System.arraycopy (buffer, curr_pos + tag_size, result, 0, length);
            curr_pos += tag_size + length;
            return result;
          }

        private byte[] getData (int length_constraint) throws GeneralSecurityException
          {
            int length = getLength ();
            if (length_constraint != length)
              {
                throw new GeneralSecurityException ("Tag length error");
              }
            return getItem (length);
          }
        
        boolean more ()
          {
            return curr_pos < buffer.length;
          }

        private byte[] getData () throws GeneralSecurityException
          {
            return getItem (getLength ());
          }
        
        int getShort () throws GeneralSecurityException
          {
            byte[] two_bytes = getData (2);
            return (two_bytes[0] * 256) + (two_bytes[1] & 0xff);
          }

        BigInteger getBigInteger () throws GeneralSecurityException
          {
            byte[] as_bytes = getData ();
            if (as_bytes.length == 0)
              {
                return null;
              }
            return new BigInteger (as_bytes);
          }

        byte getByte () throws GeneralSecurityException
          {
            return getData (1)[0];
          }

        byte[] getArray () throws GeneralSecurityException
          {
            return getData ();
          }
      }


    private static class OutputBuffer
      {
        byte[] buffer;
        int length = 1;

        OutputBuffer ()
          {
            buffer = new byte[se_buffer_length];
            buffer[0] = (byte) 0; // Success
          }

        private OutputBuffer add (byte[] parameter) throws GeneralSecurityException
          {
            if (length + parameter.length >= se_buffer_length)
              {
                throw new GeneralSecurityException ("SE output buffer exceeded!");
              }
            System.arraycopy (parameter, 0, buffer, length, parameter.length);
            length += parameter.length;
            return this;
          }
 
        byte[] getBuffer ()
          {
            return buffer;
          }

        OutputBuffer putByte (byte value) throws GeneralSecurityException
          {
            return add (new byte[] {(byte) 1, value});
          }


        OutputBuffer putArray (byte[] array) throws GeneralSecurityException
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


        OutputBuffer putShort (int value) throws GeneralSecurityException
          {
            return add (new byte[] {(byte) 0x02, (byte) ((value >> 8) & 0xff), (byte) (value & 0xff)});
          }


        OutputBuffer putBigInteger (BigInteger big) throws GeneralSecurityException
          {
            if (big == null)
              {
                return add (new byte[]{0});
              }
            return putArray (big.toByteArray ());
          }
      }


    private static byte[] singleArrayReturn (byte[] data) throws GeneralSecurityException
      {
        return new OutputBuffer ().putArray (data).getBuffer ();
      }

  
    private static byte[] errorReturn (Exception e)
      {
        byte[] msg = new byte[]{(byte) '?',(byte) '?',(byte) '?'};
        try
          {
            msg = e.getMessage ().getBytes ("UTF-8");
          }
        catch (IOException iox)
          {
          }
        byte[] error = new byte[3 + msg.length];
        error[0] = (byte) 1; // Bad
        error[1] = (byte) (msg.length >> 8);
        error[2] = (byte) (msg.length & 0xff);
        System.arraycopy (msg, 0, error, 3, msg.length);
        return error;
      }    


    /**
     * Returns device information and capabilities.<p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="6" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">device_info</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">A device-description in UTF-8 encoding</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">rsa_capabilities</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Holds the number of <code>rsa_capability</code> elements</td>
     * </tr>

     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">rsa_capability</td>
     * <td align="center" class="dbNR">short</td>
     * <td align="left" class="dbNR">A coded object where the lowest 14 bits hold the supported key-size, while
     * bit 15 indicates if there is support for setting exponent during key-generation.
     * Note: this object is repeated for each supported size</td>
     * </tr>

     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">ecc_capabilities</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Holds the number of <code>ecc_capability</code> elements</td>
     * </tr>

     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">ecc_capability</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">An UTF-8 encoded string holding the OID of a supported curve</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public static byte[] getDeviceInformation ()
      {
        try
          {
            OutputBuffer device_info = new OutputBuffer ()
// Device name
                .putArray (DEVICE_NAME.getBytes ("UTF-8"))
// RSA capabilities
                .putByte ((byte)0x02)  // Two elements
                .putShort (1024)       // Size 1
                .putShort (2048);      // Size 2
// ECC Capabilities
            device_info.putByte ((byte)ECCCapabilities.values ().length);
            for (ECCCapabilities alg : ECCCapabilities.values ())
              {
                device_info.putArray (alg.getOID ());
              }

            return device_info.getBuffer ();
          }
        catch (Exception e)
          {
            return errorReturn (e);
          }
      }


    /**
     * Enumerates supported algorithms.<p>
     * This method assumes that the invoker starts by setting the <code>previous_algorithm_id</code>
     * to <code>0xff</code> and then use the returned <code>algorithm_id</code> value as input to the next call.
     * This process should end when an <code>algorithm_uri</code> with zero length has been found.
     * The purpose of the <code>getNextAlgorithm</code> method is finding out the mappings
     * (and the capabilities...) in order to supply the proper SE local algorithm IDs
     * required by most other SE methods.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="3" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">previous_algorithm_id</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Algorithm ID in SE local notation</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="4" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">algorithm_uri</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Algorithm URI in UTF-8 coding</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">algorithm_id</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Algorithm ID in SE local notation</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public static byte[] getNextAlgorithm (byte[] parameter_block)
      {
        try
          {
            byte previous_id = new InputBuffer (parameter_block).getByte ();
            if (++previous_id < 0 || previous_id > supported_algorithms.length)
              {
                throw new GeneralSecurityException ("Bad algorithm ID");
              }
            byte[] alg_uri = new byte[0];
            if (previous_id < supported_algorithms.length)
              {
                alg_uri = supported_algorithms[previous_id].algorithm_uri;
              }
            return new OutputBuffer ()
                       .putArray (alg_uri)
                       .putByte (previous_id)
                       .getBuffer ();
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }


    /**
     * Returns the device certificate path.<p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">result</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Device certificate path.
     * It may as a minimum hold the end-entity certificate.</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public byte[] getPackedDeviceCertificatePath ()
      {
        try
          {
            return singleArrayReturn (packed_device_certificates);
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }


    private static byte[] internalRSADigestSign (PrivateKey private_key,
                                                 byte[] digest,
                                                 byte[] padding_sequence,
                                                 byte[] digest_info)
    throws GeneralSecurityException
      {
        byte[] modulus = ((RSAKey)private_key).getModulus ().toByteArray ();
        int k = modulus.length;
        if (modulus[0] == 0) k--;
        byte[] encoded_message = new byte [k];
        encoded_message[0] = (byte)0;
        encoded_message[1] = (byte)1;
        int i = k - 2 - padding_sequence.length - digest.length - digest_info.length;
        int j = 2;
        while (i-- > 0)
          {
            encoded_message[j++] = (byte)0xff;
          }
        i = 0;
        while (i < padding_sequence.length)
          {
            encoded_message[j++] = padding_sequence[i++];
          }
        System.arraycopy (digest_info, 0, encoded_message, j, digest_info.length);
        System.arraycopy (digest, 0, encoded_message, j + digest_info.length, digest.length);
        Cipher crypt = Cipher.getInstance (UNFORMATTED_RSA);
        crypt.init (Cipher.ENCRYPT_MODE, private_key);
        return crypt.doFinal (encoded_message);
      }

    private static byte[] getDigestInfo (byte algorithm) throws GeneralSecurityException
      {
        byte[] digest_info = supported_algorithms[algorithm].digest_info;
        if (digest_info == null)
          {
            throw new GeneralSecurityException ("DigestInfo missing");
          }
        return digest_info;
      }

    private byte[] internalDeviceKeyDigestSign (byte[] digest, byte algorithm) throws GeneralSecurityException
      {
        return internalRSADigestSign (device_private_key, digest, PS_PKCS1_STD, getDigestInfo (algorithm));
      }


    /**
     * Signs digested data using the device private key.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="4" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">digest</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The digested data to be signed.
     * Note that the <code>digest</code> MUST match that of <code>algorithm</code></td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">The signature algorithm in local SE notation</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">result</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Signed data</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public byte[] deviceKeyDigestSign (byte[] parameter_block)
      {
        try
          {
            InputBuffer input = new InputBuffer (parameter_block);
            return singleArrayReturn (internalDeviceKeyDigestSign (input.getArray (),
                                                                   input.getByte ()));
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }


    private static byte[] internalPrivateKeyDigestSign (byte[] digest,
                                                        byte[] private_key_handle,
                                                        byte algorithm) throws GeneralSecurityException
      {
        return internalRSADigestSign (unsealPrivateKey (private_key_handle, USER_PRIVATE_KEY),
                                      digest,
                                      PS_PKCS1_STD,
                                      getDigestInfo (algorithm));
      }


    /**
     * Signs digested data using a private key.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="5" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">digest</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The digested data to be signed.
     * Note that the <code>digest</code> MUST match that of <code>algorithm</code></td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">private_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The sealed signature key</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">The signature algorithm in local SE notation</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">result</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Signed data</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public static byte[] privateKeyDigestSign (byte[] parameter_block)
      {
        try
          {
            InputBuffer input = new InputBuffer (parameter_block);
            return singleArrayReturn (internalPrivateKeyDigestSign (input.getArray (),
                                                                    input.getArray (),
                                                                    input.getByte ()));
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }

    /**
     * Scrambles an unprotected password.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">password</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The unprotected password</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">result</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Scrambled password.
     * Note: a specific password will always generate the same scrambled value.</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public static byte[] scramblePassword (byte[] parameter_block)
      {
        try
          {
            Cipher crypt = Cipher.getInstance (PASSWORD_ENCRYPTION_MODE);
            crypt.init (Cipher.ENCRYPT_MODE, password_encryption_key);
            return singleArrayReturn (crypt.doFinal (new InputBuffer (parameter_block).getArray ()));
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }

    private static byte[] masterEncrypt (byte[] data) throws GeneralSecurityException
      {
        Cipher crypt = Cipher.getInstance (KEY_ENCRYPTION_MODE);
        byte[] iv = new byte[16];
        SecureRandom.getInstance ("SHA1PRNG").nextBytes (iv);
        crypt.init (Cipher.ENCRYPT_MODE, master_encryption_key, new IvParameterSpec (iv));
        return addArrays (iv, crypt.doFinal (data));
      }


    private static byte[] masterDecrypt (byte[] data) throws GeneralSecurityException
      {
        Cipher crypt = Cipher.getInstance (KEY_ENCRYPTION_MODE);
        crypt.init (Cipher.DECRYPT_MODE, master_encryption_key, new IvParameterSpec (data, 0, 16));
        return crypt.doFinal (data, 16, data.length - 16);
      }


    private static byte[] internalSealSecretKey (byte[] secret_key, byte exportable, byte[] endorsed_algorithms) throws GeneralSecurityException
      {
        byte[] tag = new byte[12];
        tag[0] = USER_SECRET_KEY;
        tag[1] = (byte) endorsed_algorithms.length;
        for (int i = 0; i < endorsed_algorithms.length; i++)
          {
            tag[i + 2] = endorsed_algorithms[i];
          }
        tag = addArrays (tag, secret_key);
        Mac mac = Mac.getInstance (HMAC_SHA1);
        mac.init (master_encryption_key);
        return masterEncrypt (addArrays (mac.doFinal (tag), tag));
      }

    /**
     * Seales a raw secret key.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="4" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">secret_key</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The raw secret key</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">exportable</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">This flag should be 0x01 for exportable keys otherwise it should be 0x00</td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">endorsed_algorithms</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">An array of endorsed algorithms in local SE-notation.
     * A zero-length array indicates "unrestricted" algorithm usage</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">secret_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Sealed secret key</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
     public static byte[] sealSecretKey (byte[] parameter_block)
      {
        try
          {
            InputBuffer input = new InputBuffer (parameter_block);
            return singleArrayReturn (internalSealSecretKey (input.getArray (),
                                                             input.getByte (),
                                                             input.getArray ()));
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }


    private static byte[] unsealSecretKey (byte[] secret_key_handle, byte algorithm)
    throws GeneralSecurityException
      {
        byte[] blank = masterDecrypt (secret_key_handle);
        byte[] tag = new byte[blank.length - 20];
        for (int i = 0; i < tag.length; i++)
          {
            tag[i] = blank[i + 20];
          }
        byte[] declared_mac = new byte[20];
        for (int i = 0; i < 20; i++)
          {
            declared_mac[i] = blank[i];
          }
        Mac mac = Mac.getInstance (HMAC_SHA1);
        mac.init (master_encryption_key);
        if (!compareArrays (mac.doFinal (tag), declared_mac))
          {
            throw new GeneralSecurityException ("Key integrity error");
          }
        if (tag[0] != USER_SECRET_KEY)
          {
            throw new GeneralSecurityException ("Symmetric key marker error");
          }
        int q = tag[1];
        if (q > 0)
          {
            boolean found = false;
            while (--q >= 0)
              {
                if (tag[q + 2] == algorithm)
                  {
                    found = true;
                    break;
                  }
              }
            if (!found)
              {
                throw new GeneralSecurityException ("Algorithm key usage error");
              }
          }
        byte[] key = new byte[blank.length - 32];
        for (int i = 0; i < key.length; i++)
          {
            key[i] = blank[i + 32];
          }
        return key;
      }


    static byte[] internalSealPrivateKey (byte[] encoded_private_key, byte exportable, byte key_qualifier) throws GeneralSecurityException
      {
        byte[] tag = new byte[1];
        tag[0] = key_qualifier;
        tag = addArrays (tag, encoded_private_key);
        Mac mac = Mac.getInstance (HMAC_SHA1);
        mac.init (master_encryption_key);
        return masterEncrypt (addArrays (mac.doFinal (tag), tag));
      }


    /**
     * Seales a raw private key.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="4" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">encoded_private_key</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The unprotected private key</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">exportable</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">This flag should be 0x01 for exportable keys otherwise it should be 0x00</td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">key_usage</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">See {@link #generateAttestedKeyPair(byte[]) generateAttestedKeyPair}</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">private_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Sealed private key</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public static byte[] sealPrivateKey (byte[] parameter_block)
      {
        try
          {
            InputBuffer input = new InputBuffer (parameter_block);
            return singleArrayReturn (internalSealPrivateKey (input.getArray (),
                                                              input.getByte (),
                                                              USER_PRIVATE_KEY));
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }

   // Note: This is just a "special" outside of the SE design.
    static byte[] sealDevicePrivateKey (byte[] encoded_private_key) throws GeneralSecurityException
      {
        return internalSealPrivateKey (encoded_private_key, (byte)0x00, DEVICE_PRIVATE_KEY);
      }


    private static PrivateKey unsealPrivateKey (byte[] private_key_handle, byte key_qualifier) throws GeneralSecurityException
      {
        byte[] blank = masterDecrypt (private_key_handle);
        byte[] tag = new byte[blank.length - 20];
        for (int i = 0; i < tag.length; i++)
          {
            tag[i] = blank[i + 20];
          }
        byte[] declared_mac = new byte[20];
        for (int i = 0; i < 20; i++)
          {
            declared_mac[i] = blank[i];
          }
        Mac mac = Mac.getInstance (HMAC_SHA1);
        mac.init (master_encryption_key);
        if (!compareArrays (mac.doFinal (tag), declared_mac))
          {
            throw new GeneralSecurityException ("Key integrity error");
          }
        if (tag[0] != key_qualifier)
          {
            throw new GeneralSecurityException ("Asymmetric key marker error");
          }
        byte[] key = new byte[blank.length - 21];
        for (int i = 0; i < key.length; i++)
          {
            key[i] = blank[i + 21];
          }
        PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (key);
        return KeyFactory.getInstance ("RSA").generatePrivate (key_spec);
      }


    /**
     * Generates an attested key-pair.
     * <br>Below is a KeyGen2 <code>KeyOperationRequest</code> XML fragment ...
     * <pre>  &lt;<font color="#C00000">CreateObject</font>&gt;
     &lt;<font color="#C00000">KeyPair</font> <font color="#0000C0">ID</font>="Key.1" <font color="#0000C0">KeyUsage</font>="authentication" <font color="#0000C0">Exportable</font>="false"&gt;
        &lt;<font color="#C00000">RSA</font> <font color="#0000C0">KeySize</font>="2048"/&gt;
     &lt;/<font color="#C00000">KeyPair</font>&gt;
  &lt;/<font color="#C00000">CreateObject</font>&gt;
</pre><p>
     * ... followed by a matching KeyGen2 <code>KeyOperationResponse</code> XML fragment ...
     * <pre>  &lt;<font color="#C00000">GeneratedPublicKey</font>&nbsp;<font color="#0000C0">ID</font>="Key.1" <font color="#0000C0">KeyAttestation</font>="FuW0cnn77bT ... sXd47zvG8="&gt;
     &lt;<font color="#008000">ds</font>:<font color="#C00000">KeyInfo</font>&gt;
        &lt;<font color="#008000">ds</font>:<font color="#C00000">KeyValue</font>&gt;
           &lt;<font color="#008000">ds</font>:<font color="#C00000">RSAKeyValue</font>&gt;
              &lt;<font color="#008000">ds</font>:<font color="#C00000">Modulus</font>&gt;AJMYlSOTgea0qep ... zAJvtnCtOZqC4k=&lt;/<font color="#008000">ds</font>:<font color="#C00000">Modulus</font>&gt;
              &lt;<font color="#008000">ds</font>:<font color="#C00000">Exponent</font>&gt;AQAB&lt;/<font color="#008000">ds</font>:<font color="#C00000">Exponent</font>&gt;
           &lt;/<font color="#008000">ds</font>:<font color="#C00000">RSAKeyValue</font>&gt;
        &lt;/<font color="#008000">ds</font>:<font color="#C00000">KeyValue</font>&gt;
     &lt;/<font color="#008000">ds</font>:<font color="#C00000">KeyInfo</font>&gt;
  &lt;/<font color="#C00000">GeneratedPublicKey</font>&gt;
</pre><p>
     * Key attestations are performed by the device key.&nbsp;
     * For details on the supported attestation mechanism, please consult
     * <a href="keygen2-key-attestation-1.pdf" target="_blank"><nobr>keygen2-key-attestation-1.pdf</nobr></a>
     * and
     * <a href="keygen2-key-archival.pdf" target="_blank"><nobr>keygen2-key-archival.pdf</nobr></a>.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="14" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">crypto_family</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Cryptographic family of the key to be generated.
     * 0x0 = RSA, 0x1 = ECC</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">size</td>
     * <td align="center" class="dbNR">short</td>
     * <td align="left" class="dbNR"><i>RSA only</i>: Length of the RSA key to be generated</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">optional_exponent</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR"><i>RSA only</i>: A BigInteger.toByteArray () or byte[0] holding an optional exponent value</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">named_curve</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR"><i>ECC only</i>: An UTF-8 encoded string holding the OID of the requested curve</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">attestation_algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Key attestation algorithm in local SE notation.&nbsp;
     * Currently only <code><nobr>http://xmlns.webpki.org/keygen2/1.0#algorithm.key-attestation-1</nobr></code>
     * is supported</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">exportable</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">This flag should be 0x01 for exportable keys otherwise it should be 0x00</td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">key_usage</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">This byte sets restrictions on the use of the private key</td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">nonce</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Nonce data</td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="center" colspan="3" class="dbLN"><i>The following elements are only defined if the private key should be archived</i></td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">archival_key</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Archival public key in X.509 DER encoding.
     * &nbsp;This argument is only permitted for keys with <code>key_usage</code> set to encryption</td>
     * </tr>

     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">private_key_format</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Unencrypted private key format in local SE notation to use
     * when creating <code>encrypted_private_key</code>.&nbsp;
     * Currently only <code><nobr>http://xmlns.webpki.org/keygen2/1.0#format.pkcs8</nobr></code> and
     * is supported</td>

     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">encryption_algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Symmetric key algorithm in local SE notation to use
     * for creating <code>encrypted_private_key</code>.&nbsp;
     * Currently only <code><nobr>http://www.w3.org/2001/04/xmlenc#aes128-cbc</nobr></code> and
     * <code><nobr>http://www.w3.org/2001/04/xmlenc#aes256-cbc</nobr></code> are supported</td>
     * </tr>

     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">key_wrap_algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Public key algorithm in local SE notation to use with <code>archival_key</code>
     * for creating <code>wrapped_encryption_key</code>.&nbsp;
     * Currently only <code><nobr>http://www.w3.org/2001/04/xmlenc#rsa-1_5</nobr></code> is supported</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="7" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">public_key</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Generated public key in X.509 DER encoding</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">private_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Sealed private key</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">attest_signature</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Signature attesting that the key-pair was generated inside of the SE
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="center" colspan="3" class="dbLN"><i>The following elements are
     * only available for private keys that should be archived</i></td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">encrypted_private_key</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Private key encrypted by a random symmetric key using
     * <code>encryption_algorithm</code></td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">wrapped_encryption_key</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The random symmetric key encrypted using
     * <code>key_wrap_algorithm</code> by the <code>archival_key</code></td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public byte[] generateAttestedKeyPair (byte[] parameter_block)
      {
        try
          {
            //////////////////////////////////////////////////////////
            // Create new key-pair                                  //
            //////////////////////////////////////////////////////////
            InputBuffer input = new InputBuffer (parameter_block);
            OutputBuffer output = new OutputBuffer ();
            byte crypto_type = input.getByte ();
            KeyPairGenerator kpg = null;
            if (crypto_type == (byte)0)
              {
                kpg = KeyPairGenerator.getInstance ("RSA");
                int size = input.getShort ();
                if (size != 2048 && size != 1024)
                  {
                    throw new GeneralSecurityException ("RSA key size error: " + size);
                  }
                BigInteger optional_exponent = input.getBigInteger ();
                if (optional_exponent == null)
                  {
                    kpg.initialize (size);
                  }
                else
                  {
                    kpg.initialize (new RSAKeyGenParameterSpec (size, optional_exponent));
                  }
              }
            else
              {
                kpg = KeyPairGenerator.getInstance ("EC");
                byte[] curve = input.getArray ();
                kpg.initialize(new ECGenParameterSpec (ECCCapabilities.getJCEName (curve)));
              }
            @SuppressWarnings("unused")
            byte attestation_algorithm = input.getByte ();
            KeyPair key_pair = kpg.generateKeyPair ();
            byte[] encoded_public_key = key_pair.getPublic ().getEncoded ();
            output.putArray (encoded_public_key);
            byte[] private_key = key_pair.getPrivate ().getEncoded ();
            output.putArray (internalSealPrivateKey (private_key, (byte)0x00, USER_PRIVATE_KEY));
            byte exportable = input.getByte ();
            byte key_usage = input.getByte ();
            byte[] nonce = input.getArray ();

            //////////////////////////////////////////////////////////
            // Create attestation signature package                 //
            //////////////////////////////////////////////////////////
            MessageDigest md = MessageDigest.getInstance (SHA256);
            md.update (nonce);
            md.update (exportable);
            md.update (key_usage);
            md.update (encoded_public_key);
            byte[] opt_archival_key = null;
            if (input.more ())
              {
                //////////////////////////////////////////////////////////
                // Archival: include key backup key in the attestation  //
                //////////////////////////////////////////////////////////
                md.update (opt_archival_key = input.getArray ());
              }
            output.putArray (internalRSADigestSign (device_private_key, md.digest (), PS_PKCS1_DIAS, DIGEST_INFO_SHA256));
            if (opt_archival_key != null)
              {
          
                @SuppressWarnings("unused")
                byte private_key_format = input.getByte ();
                byte encryption_algorithm = input.getByte ();
                byte key_wrap_algorithm = input.getByte ();
                if (!AES_CBC_PKCS5.equals(supported_algorithms[encryption_algorithm].jcename))
                  {
                    throw new GeneralSecurityException ("Wrong key encryption algorithm:" + supported_algorithms[encryption_algorithm].algorithm_uri);
                  }
                //////////////////////////////////////////////////////
                // Archival: generate random key to encrypt with    //
                //////////////////////////////////////////////////////
                byte[] encoder_key = new byte[(supported_algorithms[encryption_algorithm].alg_params & KEY_16) == KEY_16 ? 16 : 32];
                SecureRandom.getInstance ("SHA1PRNG").nextBytes (encoder_key);
                byte[] iv = new byte[16];
                SecureRandom.getInstance ("SHA1PRNG").nextBytes (iv);

                //////////////////////////////////////////////////////
                // Archival: encrypt private key and export it      //
                //////////////////////////////////////////////////////
                Cipher crypt = Cipher.getInstance (AES_CBC_PKCS5);
                crypt.init (Cipher.ENCRYPT_MODE,
                            new SecretKeySpec (encoder_key, "AES"),
                            new IvParameterSpec (iv));
                output.putArray (addArrays (iv, crypt.doFinal (private_key)));

                //////////////////////////////////////////////////////
                // Archival: encrypt the random key and export it   //
                //////////////////////////////////////////////////////
                crypt = Cipher.getInstance (supported_algorithms[key_wrap_algorithm].jcename);
                crypt.init (Cipher.ENCRYPT_MODE,
                            KeyFactory.getInstance ("RSA").generatePublic (new X509EncodedKeySpec (opt_archival_key)));
                output.putArray (crypt.doFinal (encoder_key));
              }

            //////////////////////////////////////////////////////////
            // Return completed structure                           //
            //////////////////////////////////////////////////////////
            return output.getBuffer ();
          }
        catch (Exception e)
          {
            return errorReturn (e);
          }
      }


    /**
     * Encrypts or decrypts data using a secret key.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="6" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">encrypt_flag</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">This flag should be 0x01 for encryption and 0x00 for decryption</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">data</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The data to be encrypted or decrypted.
     * Note: the length may not exceed 3500 bytes</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">secret_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The sealed encryption key</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">The encryption algorithm in local SE notation</td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">iv</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Optional IV vector.  MUST be byte[0] for algorithms not requiring an IV</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">result</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Encrypted or decrypted data</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public static byte[] symmetricKeyEncrypt (byte[] parameter_block)
      {
        try
          {
            InputBuffer input = new InputBuffer (parameter_block);
            byte encrypt_flag = input.getByte ();
            byte[] data = input.getArray ();
            byte[] secret_key_handle = input.getArray ();
            byte algorithm = input.getByte ();
            int alg_params = supported_algorithms[algorithm].alg_params;
            byte[] iv = input.getArray ();
            if ((alg_params & IV_REQUIRED) == 0 && iv.length != 0)
              {
                throw new GeneralSecurityException ("IV not zero for algorithm: " + algorithm);
              }

            byte[] secret_key = unsealSecretKey (secret_key_handle, algorithm);
            SecretKeySpec sks = new SecretKeySpec (secret_key, "AES");

            if (((alg_params & KEY_16) != 0 && secret_key.length != 16) ||
                ((alg_params & KEY_32) != 0 && secret_key.length != 32))
              {
                throw new GeneralSecurityException ("Wrong key size for algorithm: " + algorithm + " l=" + secret_key.length);
              }

            Cipher cipher = Cipher.getInstance (supported_algorithms[algorithm].jcename);
            int mode = encrypt_flag != 0 ? 
                          ((alg_params & IS_KEY_WRAPPER) != 0 ? Cipher.WRAP_MODE : Cipher.ENCRYPT_MODE)
                                    : 
                          ((alg_params & IS_KEY_WRAPPER) != 0 ? Cipher.UNWRAP_MODE : Cipher.DECRYPT_MODE);

            if ((alg_params & IV_REQUIRED) != 0)
              {
                if (iv.length != 16)
                  {
                    throw new GeneralSecurityException ("IV missing for algorithm: " + algorithm);
                  }
                cipher.init (mode, sks, new IvParameterSpec (iv));
                return singleArrayReturn (cipher.doFinal (data));
              }
            else if ((alg_params & IS_KEY_WRAPPER) != 0)
              {
                cipher.init (mode, sks);
                if (encrypt_flag != 0)
                  {
                    return singleArrayReturn (cipher.wrap (new SecretKeySpec (data, "RAW")));
                  }
                return singleArrayReturn (cipher.unwrap (data, "RAW", Cipher.SECRET_KEY).getEncoded ());
              }
            else
              {
                cipher.init (mode, sks);
                return singleArrayReturn (cipher.doFinal (data));
              }
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }


    private byte[] internalDeviceKeyDecrypt (byte[] data, byte algorithm) throws GeneralSecurityException
      {
        Cipher crypt = Cipher.getInstance (supported_algorithms[algorithm].jcename);
        crypt.init (Cipher.DECRYPT_MODE, device_private_key);
        return crypt.doFinal (data);
      }
  
    /**
     * Decrypts data using the device private key.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="3" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">data</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The data to be decrypted</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">The decryption algorithm in local SE notation.
     * Note: due to the fact that device keys also function as key attestation keys,
     * only PKCS&nbsp;#1 style of decryption algorithms are accepted.</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">result</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Decrypted data</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public byte[] deviceKeyDecrypt (byte[] parameter_block)
      {
        try
          {
            InputBuffer input = new InputBuffer (parameter_block);
            byte[] data = input.getArray ();
            byte algorithm = input.getByte ();
            if ((supported_algorithms[algorithm].alg_params & RAW_RSA) != 0)
              {
                throw new GeneralSecurityException ("RAW RSA forbidden for device keys!");
              }
            return singleArrayReturn (internalDeviceKeyDecrypt (data, algorithm));
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }
  

    private static byte[] internalPrivateKeyDecrypt (byte[] data,
                                                     byte[] private_key_handle,
                                                     byte algorithm)
    throws GeneralSecurityException
      {
        Cipher cipher = Cipher.getInstance (supported_algorithms[algorithm].jcename);
        cipher.init (Cipher.DECRYPT_MODE, unsealPrivateKey (private_key_handle, USER_PRIVATE_KEY));
        return cipher.doFinal (data);
      }

    /**
     * Decrypts data using a private key.<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="5" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">data</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The data to be signed</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">private_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The sealed signature key</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">The decryption algorithm in local SE notation</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">result</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Decrypted data</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public static byte[] privateKeyDecrypt (byte[] parameter_block)
      {
        try
          {
            InputBuffer input = new InputBuffer (parameter_block);
            return singleArrayReturn (internalPrivateKeyDecrypt (input.getArray (),
                                                                 input.getArray (),
                                                                 input.getByte ()));
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }


    /**
     * Creates a Keyed-Hash Message Authentication Code (HMAC).<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="5" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">data</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The data to generate a HMAC of.
     * Note: the length may not exceed 3500 bytes</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">secret_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The sealed secret key used as HMAC key</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">The HMAC algorithm in local SE notation</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">result</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">HMAC data</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public static byte[] symmetricKeyHMAC (byte[] parameter_block)
      {
        try
          {
            InputBuffer input = new InputBuffer (parameter_block);
            byte[] data = input.getArray ();
            byte[] secret_key_handle = input.getArray ();
            byte algorithm = input.getByte ();

            Mac mac = Mac.getInstance (supported_algorithms[algorithm].jcename);
            mac.init (new SecretKeySpec (unsealSecretKey (secret_key_handle, algorithm), "RAW"));  // Note: any length is OK in HMAC
            return singleArrayReturn (mac.doFinal (data));
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }


    /**
     * Provisions a KeyGen2 "piggybacked" symmetric key. Below is an example:      
     * <pre>  &lt;<font color="#C00000">CertifiedPublicKey</font> <font color="#0000C0">ID</font>="Key.1"&gt;
     &lt;<font color="#008000">ds</font>:<font color="#C00000">X509Data</font>&gt;
        &lt;<font color="#008000">ds</font>:<font color="#C00000">X509Certificate</font>&gt;MIIDnTCCAo...fCc6PBLPWMYn4dPY=&lt;/<font color="#008000">ds</font>:<font color="#C00000">X509Certificate</font>&gt;
     &lt;/<font color="#008000">ds</font>:<font color="#C00000">X509Data</font>&gt;
     &lt;<font color="#C00000">PiggybackedSymmetricKey</font> <font color="#0000C0">EndorsedAlgorithms</font>="http://www.w3.org/2000/09/xmldsig#hmac-sha1"
                              <font color="#0000C0">MAC</font>="14z1RfdoVeDqYfSviPWZD4c2AL4="&gt;
        &lt;<font color="#008000">xenc</font>:<font color="#C00000">EncryptedKey</font>&gt;
           &lt;<font color="#008000">xenc</font>:<font color="#C00000">EncryptionMethod</font> <font color="#0000C0">Algorithm</font>="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/&gt;
           &lt;<font color="#008000">xenc</font>:<font color="#C00000">CipherData</font>&gt;
              &lt;<font color="#008000">xenc</font>:<font color="#C00000">CipherValue</font>&gt;VA2TbKUq...HQk9HoOIwCeSs=&lt;/<font color="#008000">xenc</font>:<font color="#C00000">CipherValue</font>&gt;
           &lt;/<font color="#008000">xenc</font>:<font color="#C00000">CipherData</font>&gt;
        &lt;/<font color="#008000">xenc</font>:<font color="#C00000">EncryptedKey</font>&gt;
     &lt;/<font color="#C00000">PiggybackedSymmetricKey</font>&gt;
  &lt;/<font color="#C00000">CertifiedPublicKey</font>&gt;
</pre>
<p>
     * <b>Parameters:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="8" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">piggyback_mac_algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">Key &quot;piggyback&quot; MAC algorithm in local SE notation.&nbsp;
     * Currently only <code><nobr>http://xmlns.webpki.org/keygen2/1.0#algorithm.mac-piggyback-1</nobr></code>
     * is supported</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">encryption_algorithm</td>
     * <td align="center" class="dbNR">byte</td>
     * <td align="left" class="dbNR">The XML encryption <code>Algorithm</code> expressed in local SE notation.&nbsp;
     * Currently only <code><nobr>http://www.w3.org/2001/04/xmlenc#rsa-1_5</nobr></code> is supported</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">encrypted_symmetric_key</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The encrypted data as featured in the <code>CipherValue</code> element</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">private_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The sealed private key associated with the <code>CertifiedPublicKey</code>
     * element embedding the <code>PiggybackedSymmetricKey</code> element</td>
     * </tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">endorsed_algorithms</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">An array of SE-local identifiers to 
     * the <code>EndorsedAlgorithms</code> as declared in the <code>PiggybackedSymmetricKey</code> element
     * where the algorithm URIs have been sorted in alphabetical order</td>
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">mac</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">The <code>MAC</code> as declared in the
     * <code>PiggybackedSymmetricKey</code> element.
     * </tr>
     *
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">nonce</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Nonce data</td>
     * </tr>
     *
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table><p>
     * <b>Returns:</b><p>
     * <table cellpadding="0" cellspacing="0"><tr>
     * <td class="dbTL" align="center" style="background-color:#E0E0E0">Variable&nbsp;Name</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Data&nbsp;Type</td>
     * <td class="dbTR" align="center" style="background-color:#E0E0E0">Comment</td>
     * <td rowspan="2" background="vshaddow.gif" width="2"></td></tr>
     * 
     * <tr bgcolor="ivory">
     * <td align="left" class="dbNL">secret_key_handle</td>
     * <td align="center" class="dbNR">byte[]</td>
     * <td align="left" class="dbNR">Sealed secret key</td>
     * </tr>
     * 
     * <tr><td colspan="4" background="hshaddow.gif" height="2"></td></tr>
     * 
     * </table>
     */
    public static byte[] provisionPiggybackedSymmetricKey (byte[] parameter_block)
      {
        try
          {
            InputBuffer input = new InputBuffer (parameter_block);
            @SuppressWarnings("unused")
            byte piggyback_mac_algorithm = input.getByte ();
            byte encryption_algorithm = input.getByte ();
            byte[] encrypted_symmetric_key = input.getArray ();
            byte[] private_key_handle = input.getArray ();
            byte[] endorsed_algorithms = input.getArray ();
            byte[] declared_mac = input.getArray ();
            byte[] nonce = input.getArray ();

            byte[] symmetric_key = internalPrivateKeyDecrypt (encrypted_symmetric_key,
                                                              private_key_handle,
                                                              encryption_algorithm);
            Mac mac = Mac.getInstance (HMAC_SHA256);
            mac.init (new SecretKeySpec (nonce, "RAW"));  // Note: any length is OK in HMACSHA
            for (byte alg_id : endorsed_algorithms)
              {
                mac.update (supported_algorithms[alg_id].algorithm_uri);
                mac.update ((byte)0);  // The KeyGen2 spec calls for sorted and null-terminated alg strings
              }
            mac.update (symmetric_key);
            byte[] rmac = mac.doFinal ();
            boolean err = false;
            if (rmac.length != declared_mac.length)
              {
                err = true;
              }
            else for (int i = 0; i < rmac.length; i++)
              {
                if (rmac[i] != declared_mac[i])
                  {
                    err = true;
                    break;
                  }
              }
            if (err)
              {
                throw new GeneralSecurityException ("MAC error for piggybacked key");
              }
            return singleArrayReturn (internalSealSecretKey (symmetric_key,
                                                             (byte)0x00,
                                                             endorsed_algorithms[0] == 0 ? new byte[0] : endorsed_algorithms));
          }
        catch (GeneralSecurityException gse)
          {
            return errorReturn (gse);
          }
      }

  }
