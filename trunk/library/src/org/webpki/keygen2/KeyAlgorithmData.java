package org.webpki.keygen2;

import java.io.IOException;

import org.webpki.crypto.ECDomains;
import org.webpki.util.ArrayUtil;

public abstract class KeyAlgorithmData
  {
    public abstract byte[] getSKSValue () throws IOException;
    
    byte[] short2bytes (int s)
      {
        return new byte[]{(byte)(s >>> 8), (byte)s};
      }


    public static class RSA extends KeyAlgorithmData
      {
        int key_size;
    
        int fixed_exponent;  // May be 0
    
        public RSA (int key_size, int fixed_exponent)
          {
            this.key_size = key_size;
            this.fixed_exponent = fixed_exponent;
          }
    
    
        public int getKeySize ()
          {
            return key_size;
          }
    
    
        public int getFixedExponent ()
          {
            return fixed_exponent;
          }


        @Override
        public byte[] getSKSValue () throws IOException
          {
            return ArrayUtil.add (
                ArrayUtil.add (new byte[]{CryptoConstants.RSA_KEY}, short2bytes (key_size)),
                ArrayUtil.add (short2bytes (fixed_exponent >>> 16), short2bytes (fixed_exponent))
                          );
          }

      }


    public static class EC extends KeyAlgorithmData
      {
        ECDomains named_curve;
    
        public EC (ECDomains named_curve)
          {
            this.named_curve = named_curve;
          }
    
    
        public ECDomains getNamedCurve ()
          {
            return named_curve;
          }

        
        @Override
        public byte[] getSKSValue () throws IOException
          {
            return ArrayUtil.add (
                ArrayUtil.add (new byte[]{CryptoConstants.ECC_KEY}, short2bytes (named_curve.getURI ().length ())),
                named_curve.getURI ().getBytes ("UTF-8")
                          );
          }
      }

  }

