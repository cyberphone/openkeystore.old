package org.webpki.sks.ws;

public interface WSSpecific
  {
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
  }
