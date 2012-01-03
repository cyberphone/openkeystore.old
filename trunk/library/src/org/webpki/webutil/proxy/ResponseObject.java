package org.webpki.webutil.proxy;

import java.io.Serializable;


/**   
* HTTP proxy object containing a serialized HTTP response
* which is tunneled through the proxy out to the requester.
*/
public class ResponseObject extends ClientObject implements Serializable
  {
    private static final long serialVersionUID = 1L;

    byte[] data;
    
    String mime_type;

    ////////////////////////////////////////////////////////
    // Due to the multi-channel proxy, calls need IDs
    ////////////////////////////////////////////////////////
    long caller_id;
    

    public ResponseObject (byte[] data,
                           String mime_type,
                           RequestObject ro)
      {
        super (ro.client_id);
        this.data = data;
        this.mime_type = mime_type;
        this.caller_id = ro.caller_id;
      }

  }
