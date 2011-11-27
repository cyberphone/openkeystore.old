package org.webpki.sks.ws;

import org.webpki.sks.SKSException;

public interface WSSpecific
  {
    /**
     * Non-SKS method for SKS devices
     * 
     * @return devices ids
     */
    String[] listDevices () throws SKSException;

    /**
     * Non-SKS method for getting WS interface version
     * 
     * @return version string
     */
    String getVersion ();
    
    /**
     * Non-SKS method for logging data.
     * Transfers log data from SKS applications to the WS log
     * 
     * @param event
     */
    void logEvent (String event);

    /**
     * Setup WS driver property
     */
    boolean setTrustedGUIAuthorizationProvider (TrustedGUIAuthorization tga_provider);

    /**
     * Setup WS device property
     */
    void setDeviceID (String device_id);
  }
