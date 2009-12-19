package org.webpki.sks;

import java.io.IOException;

import java.util.GregorianCalendar;


/**
 * TOTP (Time-based) OTP provider based on HOTP.  Only instanciated indirectly through OTPProvider.
 */
public class TOTPProvider extends HOTPBaseProvider implements PropertyBagConsumer
  {
    static PropertyBagDefinition props = 
       new PropertyBagDefinition (org.webpki.keygen2.KeyGen2URIs.OTPPROVIDERS.IETF_TOTP);

    static
      {
        props.add (HOTP_ATTR_CYCLE);
        props.add (HOTP_ATTR_DIGITS);
        props.addOptional (HOTP_ATTR_LOGIN_ID);
      }


    public PropertyBagDefinition getPropertyBagDefinition () throws IOException
      {
        return props;
      }


    TOTPProvider () // Only used by the framework
      {
      }


    OTPProvider.OTP_TYPES getOTPTypeImplementation ()
      {
        return OTPProvider.OTP_TYPES.TIME;
      }


    public String getName ()
      {
        return "TOTP 1.0";
      }


    int getCycleImplementation () throws IOException
      {
        return property_bag.getInteger ("Cycle");
      }


    String generateImplementation () throws IOException
      {
        ///////////////////////////////////////////////
        // Get time
        ///////////////////////////////////////////////
        long time = new GregorianCalendar ().getTimeInMillis ();
        time /= (getCycleImplementation () * 1000);

        ///////////////////////////////////////////////
        // Perform the real stuff
        ///////////////////////////////////////////////
        return coreHOTPAlgorithm (time);
      }

  }
