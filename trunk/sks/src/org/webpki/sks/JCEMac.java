package org.webpki.sks;

import java.io.IOException;

import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;

import javax.crypto.MacSpi;

import org.webpki.util.WrappedException;
import org.webpki.util.ArrayUtil;

import org.webpki.crypto.MacAlgorithms;


/**This class must be extended.
 *
 */
public abstract class JCEMac extends MacSpi
  {
    JCEKeyStore.JCESecretKey secret_key;

    MacAlgorithms mac_algorithm;

    int mac_length;

    byte[] data;


    public JCEMac (MacAlgorithms mac_algorithm, int mac_length)
      {
        this.mac_algorithm = mac_algorithm;
        this.mac_length = mac_length;
      }

    public Object clone ()
      {
        return null;
      }

    private byte[] createData ()
      {
        if (data == null)
          {
            data = new byte[0];
          }
        return data;
      }

    protected byte[] engineDoFinal ()
      {
        createData ();
        byte[] result = null;
        try
          {
            secret_key.open ();
            secret_key.checkSymmetricKeyAndAlgorithm (mac_algorithm.getURI ());
            result = secret_key.sks.symmetricKeyHMAC (data,
                                                      secret_key.key_id,
                                                      mac_algorithm,
                                                      secret_key.binary_optional_pin,
                                                      secret_key.key_auth_callback);
            secret_key.conditionalClose ();
          }
        catch (IOException e)
          {
            secret_key.conditionalClose ();
            throw new WrappedException (e);
          }
        return result;
      }


    protected int engineGetMacLength ()
      {
        return mac_length;
      } 

    protected void engineInit (Key key, AlgorithmParameterSpec params)
    throws InvalidKeyException, InvalidAlgorithmParameterException
      {
        if (params != null)
          {
            throw new InvalidAlgorithmParameterException ("\"params\" must be null");
          }

        if (!(key instanceof JCEKeyStore.JCESecretKey))
          {
            throw new InvalidKeyException ("Secret key must be an instance of" +
                    JCEKeyStore.JCESecretKey.class.getName ());
          }
        secret_key = (JCEKeyStore.JCESecretKey) key;
      }


    protected void engineReset ()
      {
        data = null;
      }

    protected void engineUpdate (byte input)
      {
        ArrayUtil.add (createData (), new byte[]{input});
      } 


    protected void engineUpdate (byte[] input, int offset, int len)
      {
        if (input.length == len)
          {
            ArrayUtil.add (createData (), input);
          }
        else
          {
            byte[] new_data = new byte[len];
            System.arraycopy (input, offset, new_data, 0, len);
            ArrayUtil.add (createData (), new_data);
          }
      }


    public static class MD5 extends JCEMac
      {
        public MD5 ()
          {
            super (MacAlgorithms.HMAC_MD5, 16);
          }
      }


    public static class SHA1 extends JCEMac
      {
        public SHA1 ()
          {
            super (MacAlgorithms.HMAC_SHA1, 20);
          }
      }


    public static class SHA256 extends JCEMac
      {
        public SHA256 ()
          {
            super (MacAlgorithms.HMAC_SHA256, 32);
          }
      }

    public static class SHA384 extends JCEMac
      {
        public SHA384 ()
          {
            super (MacAlgorithms.HMAC_SHA384, 48);
          }
      }

    public static class SHA512 extends JCEMac
      {
        public SHA512 ()
          {
            super (MacAlgorithms.HMAC_SHA512, 64);
          }
      }

  }
