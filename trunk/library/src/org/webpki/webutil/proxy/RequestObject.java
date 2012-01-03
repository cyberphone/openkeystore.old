package org.webpki.webutil.proxy;

import java.io.Serializable;


/**
* Proxy object containing a serialized XML request which is to be delivered to
* the local SPOC server.
*/
public class RequestObject implements Serializable
  {
    private static final long serialVersionUID = 1L;

    byte[] data;

    ////////////////////////////////////////////////////////
    // Due to the multi-channel proxy, calls need IDs
    ////////////////////////////////////////////////////////
    long caller_id;
    
    String client_id;

    public byte[] getData ()
      {
        return data;
      }
    
    public void setClientID (String client_id)
    {
        this.client_id = client_id;
    }

    public RequestObject (byte[] data)
      {
        this.data = data;
      }

  }
