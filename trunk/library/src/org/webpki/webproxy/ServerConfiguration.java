/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.webproxy;

import java.io.Serializable;

/**
 * HTTP proxy object containing a serialized server configuration which is sent
 * from the client proxy to the server proxy during startup.
 */
public class ServerConfiguration extends ClientObject implements Serializable
  {
    private static final long serialVersionUID = 1L;

    /**
     * Returns the version of the proxy scheme.
     * <p>
     * Version matching is performed by the proxy server and client during the
     * establishment of the first proxy channel.
     * 
     * @return A proxy version string.
     */
    public static String getVersion ()
      {
        return "1.0";
      }

    int proxy_timeout;
    int request_timeout;
    int response_timeout;
    boolean chunked_support;
    boolean debug;

    public ServerConfiguration (int proxy_timeout,
                                int request_timeout,
                                int response_timeout, 
                                boolean chunked_support,
                                String client_id,
                                boolean debug)
      {
        super (client_id);
        this.proxy_timeout = proxy_timeout;
        this.request_timeout = request_timeout;
        this.response_timeout = response_timeout;
        this.chunked_support = chunked_support;
        this.debug = debug;
      }

  }
