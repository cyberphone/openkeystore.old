package org.webpki.sks.test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.webpki.util.ArrayUtil;

public class ASN1
  {
    static final byte[] RSA_ALGORITHM_OID    = {0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x01};
    static final byte[] EC_ALGORITHM_OID     = {0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01}; 
    static final byte[] EC_NAMED_CURVE_P256  = {0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x03, 0x01, 0x07};

    static final int ASN1_SEQUENCE           = 0x30;
    static final int ASN1_OBJECT_IDENTIFIER  = 0x06;
    static final int ASN1_INTEGER            = 0x02;
    static final int ASN1_NULL               = 0x05;
    static final int ASN1_BISTRING           = 0x03;
    static final int ASN1_EXPLICIT_CONTEXT_0 = 0xA0;

    static final int MAX_BUFFER = 16000;

    static byte[] buffer = new byte[MAX_BUFFER];
    static int index;
    static int max_buflen;
    static int length;
    
    static class SKSPublicKey
      {
        boolean rsa;
        byte[] exp_or_y;
        byte[] mod_or_x;
      }
    
    static public void main (String[] args)
      {
        if (args.length != 2 || !(args[0].equals ("p") || args[0].equals ("c")))
          {
            System.out.println ("ASN1 p|c input-file\n  p = public key, c = certificate");
            System.exit (3);
          }
        try
          {
            byte[] data = ArrayUtil.readFile (args[1]);
            System.out.println ("KEY L=" + (args[0].equals ("p") ? getPublicKey (data) : getPublicKeyFromCertificate (data)).length);
          }
        catch (GeneralSecurityException e)
          {
            e.printStackTrace();
          }
        catch (IOException e)
          {
            e.printStackTrace();
          }
      }

    static byte[] getPublicKeyFromCertificate (byte[] data) throws GeneralSecurityException
      {
        init (data);
        getObject (ASN1_SEQUENCE);           // Outer SEQUENCE
        getObject (ASN1_SEQUENCE);             // Inner SEQUENCE (TBSCertificate)
        scanObject (ASN1_EXPLICIT_CONTEXT_0);    // [0] Version - Just scan over
        scanObject (ASN1_INTEGER);               // Serial Number - Just scan over
        scanObject (ASN1_SEQUENCE);              // Signature - Just scan over
        scanObject (ASN1_SEQUENCE);              // Issuer - Just scan over
        scanObject (ASN1_SEQUENCE);              // Validity - Just scan over
        scanObject (ASN1_SEQUENCE);              // Subject - Just scan over
        return returnPublicKey ();               // SubjectPublicKeyInfo
      }

    static void scanObject (int tag) throws GeneralSecurityException
      {
        getObject (tag);
        index += length;
      }

    static byte[] returnPublicKey () throws GeneralSecurityException
      {
        int i = index;
        parsePublicKey ();
        byte[] public_key = new byte[length = index - i];
        System.arraycopy (buffer, index - length, public_key, 0, length);
        return public_key;
      }

    static SKSPublicKey parsePublicKey () throws GeneralSecurityException
      {
        SKSPublicKey pub_key = new SKSPublicKey ();
        getObject (ASN1_SEQUENCE);
        int i = index;
        int l = length;
        getObject (ASN1_SEQUENCE);
        getObject (ASN1_OBJECT_IDENTIFIER);
        if (pub_key.rsa = oidMatch (RSA_ALGORITHM_OID))
          {
            getObject (ASN1_NULL);
            getBitString ();
            getObject (ASN1_SEQUENCE);
            getObject (ASN1_INTEGER);
            index += length;
            getObject (ASN1_INTEGER);
          }
        else if (oidMatch (EC_ALGORITHM_OID))
          {
            getObject (ASN1_OBJECT_IDENTIFIER);
            if (!oidMatch (EC_NAMED_CURVE_P256)) throw new GeneralSecurityException ("P-256 OID expected");
            getBitString ();
            if (length != 65) throw new GeneralSecurityException ("Incorrect ECPoint length");
            if (buffer[index] != 0x04) throw new GeneralSecurityException ("Only uncompressed EC support");
          }
        else
          {
            throw new GeneralSecurityException ("Unexpected OID");
          }
       index += length;
       if (i != index - l) throw new GeneralSecurityException ("Public key length error");
       return pub_key;
      }

    private static void getBitString () throws GeneralSecurityException
      {
        getObject (ASN1_BISTRING);
        if (buffer[index++] != 0x00) throw new GeneralSecurityException ("Unexpectd bitfield unused bit");
        length--;
      }

    static boolean oidMatch (byte[] oid)
      {
        if (length != oid.length) return false;
        for (int q = 0; q < length; q++)
          {
            if (buffer[index + q] != oid[q])
              {
                return false;
              }
          }
        index += length;
        return true;
      }

    static byte[] getPublicKey (byte[] data) throws GeneralSecurityException
      {
        init (data);
        return returnPublicKey ();
      }

    static void init (byte[] data) throws GeneralSecurityException
      {
        if (data.length > MAX_BUFFER) throw new GeneralSecurityException ("Object too long");
        System.arraycopy (data, 0, buffer, 0, max_buflen = data.length);
        index = 0;
      }

    static void getObject (int tag) throws GeneralSecurityException
      {
        if ((buffer[index++] & 0xFF) != tag) throw new GeneralSecurityException ("Unexpected tag: " + tag);
        length = buffer[index++] & 0xFF;
        if ((length & 0x80) != 0)
          {
            int q = length & 0x7F;
            length = 0;
            while (q-- > 0)
              {
                length <<= 8;
                length += buffer[index++] & 0xFF;
              }
          }
        if (length < 0 || index + length > max_buflen) throw new GeneralSecurityException ("Length range error: " + length);
        System.out.println ("TAG=" + tag + " I=" + index + " L=" + length);
      }


  }
