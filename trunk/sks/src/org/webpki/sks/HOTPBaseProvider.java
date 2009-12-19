package org.webpki.sks;

import java.io.IOException;

import org.webpki.crypto.MacAlgorithms;

import org.webpki.keygen2.CredentialDeploymentRequestDecoder;


/**
 * Common class for HOTP (RFC 4226) derived providers.
 */
abstract class HOTPBaseProvider extends OTPProvider
  {

    static final String HOTP_ATTR_COUNTER = "Counter";

    static final String HOTP_ATTR_DIGITS = "Digits";

    static final String HOTP_ATTR_LOGIN_ID = "LoginID";

    static final String HOTP_ATTR_C_LENGTH = "CLength";

    static final String HOTP_ATTR_CYCLE = "Cycle";


    private static final int[] DIGITS_POWER 
         // 0 1  2   3    4     5      6       7        8
         = {1,10,100,1000,10000,100000,1000000,10000000,100000000};

    HOTPBaseProvider () // Only used by the framework
      {
      }


    String coreHOTPAlgorithm (long input) throws IOException
      {
        ///////////////////////////////////////////////
        // Convert input to byte[]
        ///////////////////////////////////////////////
        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--)
          {
            data[i] = (byte) (input & 0xff);
            input >>= 8;
          }

        ///////////////////////////////////////////////
        // Execute the HMAC
        ///////////////////////////////////////////////
        byte [] hash = ((HmacProvider) key_conn).mac (data, MacAlgorithms.HMAC_SHA1);

        ///////////////////////////////////////////////
        // Perform truncation and output formatting
        ///////////////////////////////////////////////
        int digits = property_bag.getInteger ("Digits");
        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset]     & 0x7f) << 24)
                   | ((hash[offset + 1] & 0xff) << 16)
                   | ((hash[offset + 2] & 0xff) <<  8)
                   |  (hash[offset + 3] & 0xff);
        String result = String.valueOf (binary % DIGITS_POWER[digits]);
        while (result.length () < digits)
          {
            result = "0" + result;
          }
        return result;
      }


    boolean hMacBottomOperation ()
      {
        return true;
      }


    public void parse (CredentialDeploymentRequestDecoder.PropertyBag property_bag, KeyDescriptor key_descriptor) throws IOException
      {
        getPropertyBagDefinition ().parse (property_bag);
      }

  }
