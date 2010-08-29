package org.webpki.hlca;

import java.io.IOException;


/**
 * Challenge/Response OTP provider based on HOTP.  Only instanciated indirectly through OTPProvider.
 * This implementation supports a basic version where a service gives a numeric
 * challenge to a client who generates a response based on the challenge and the key.
 */
public class OCRAProvider extends HOTPBaseProvider implements PropertyBagConsumer
  {
    static PropertyBagDefinition props = 
       new PropertyBagDefinition (org.webpki.keygen2.KeyGen2URIs.OTPPROVIDERS.IETF_OCRA);

    static
      {
        props.add (HOTP_ATTR_C_LENGTH);
        props.add (HOTP_ATTR_DIGITS);
        props.addOptional (HOTP_ATTR_LOGIN_ID);
      }


    public PropertyBagDefinition getPropertyBagDefinition () throws IOException
      {
        return props;
      }


    OCRAProvider () // Only used by the framework
      {
      }


    OTPProvider.OTP_TYPES getOTPTypeImplementation ()
      {
        return OTPProvider.OTP_TYPES.CHALLENGE_RESPONSE;
      }


    public String getName ()
      {
        return "OCRA 1.0";
      }


    int getChallengeLengthImplementation () throws IOException
      {
        return property_bag.getInteger ("CLength");
      }


    String generateImplementation (String challenge) throws IOException
      {
        ///////////////////////////////////////////////
        // Perform the real stuff
        ///////////////////////////////////////////////
        return coreHOTPAlgorithm (new Long (challenge));
      }

  }
