package org.webpki.keygen2;

import org.webpki.crypto.ECDomains;

public abstract class KeyAlgorithmData
  {

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

        
        public String getNamedCurveURI ()
          {
            return named_curve.getURI ();
          }
      }

  }

