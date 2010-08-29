package org.webpki.hlca;

import java.io.IOException;


/**
 * HOTP (RFC 4226) provider.  Only instanciated indirectly through OTPProvider.
 */
public class HOTPProvider extends HOTPBaseProvider implements PropertyBagConsumer
  {
    static PropertyBagDefinition props = 
       new PropertyBagDefinition (org.webpki.keygen2.KeyGen2URIs.OTPPROVIDERS.IETF_HOTP);

    static
      {
        props.addWritable (HOTP_ATTR_COUNTER);
        props.add (HOTP_ATTR_DIGITS);
        props.addOptional (HOTP_ATTR_LOGIN_ID);
      }


    public PropertyBagDefinition getPropertyBagDefinition () throws IOException
      {
        return props;
      }


    HOTPProvider () // Only used by the framework 
      {
      }


    public String getName ()
      {
        return "HOTP 1.0";
      }


    OTPProvider.OTP_TYPES getOTPTypeImplementation ()
      {
        return OTPProvider.OTP_TYPES.EVENT;
      }


    String generateImplementation () throws IOException
      {
        ///////////////////////////////////////////////
        // Get and update the counter
        ///////////////////////////////////////////////
        int counter = property_bag.getInteger ("Counter");
        property_bag.setInteger ("Counter", counter + 1);

        ///////////////////////////////////////////////
        // Perform the real stuff
        ///////////////////////////////////////////////
        return coreHOTPAlgorithm (counter);
      }

  }
