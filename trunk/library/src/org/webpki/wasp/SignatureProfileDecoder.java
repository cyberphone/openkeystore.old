// Interface for WASP "SignatureProfile" XML decoder objects

package org.webpki.wasp;

public interface SignatureProfileDecoder
  {

    boolean hasSupportedParameters ();

    SignatureProfileResponseEncoder createSignatureProfileResponseEncoder ();

  }
