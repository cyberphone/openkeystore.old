/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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
package org.webpki.securityproxy.test.common;

import org.webpki.securityproxy.JavaRequestInterface;

public class SampleRequestObject implements JavaRequestInterface
  {
    private static final long serialVersionUID = 1L;

    private double x;
 
    private double y;
    
    private long server_wait;
    
    public double getX ()
      {
        return x;
      }

    public double getY ()
      {
        return y;
      }

    public long getServerWait ()
      {
        return server_wait;
      }
    
    public SampleRequestObject (double x, double y, long server_wait)
      {
        this.x = x;
        this.y = y;
        this.server_wait = server_wait;
      }
  }
