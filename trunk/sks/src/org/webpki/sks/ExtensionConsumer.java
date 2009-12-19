package org.webpki.sks;

import java.io.IOException;


/**
 * Extension consumer interface
 */
public interface ExtensionConsumer
  {
    /**
     * Return the type URI for this extension.
     */
    public String getTypeURI ();

    /**
     * Return a descriptive but short name for this extension.
     */
    public String getName ();

    /**
     * Called during provisioning to give the extension consumer an opportunity verifying the extension.
     * @param data The binary extension data.
     * @param key_descriptor The key that is associated with the extension.
     * @throws IOException if there are parsing errors.
    */
    public void parse (byte[] data, KeyDescriptor key_descriptor) throws IOException;
  }
