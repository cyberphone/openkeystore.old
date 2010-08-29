package org.webpki.hlca;

import java.io.IOException;

import org.webpki.keygen2.CredentialDeploymentRequestDecoder;


/**
 * Property bag consumer interface
 */
public interface PropertyBagConsumer
  {
    /**
    * In order to validate a property bag during provisioning each consumer
    * must offer a definition object
    */
    public PropertyBagDefinition getPropertyBagDefinition () throws IOException;

    public void parse (CredentialDeploymentRequestDecoder.PropertyBag prop_bag, KeyDescriptor key_descriptor) throws IOException;

    public String getName ();

  }
