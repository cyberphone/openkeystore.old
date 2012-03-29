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
package org.webpki.securityproxy.test.client;

import org.webpki.net.HTTPSWrapper;

/**
 * Security proxy test client. 
 *
 */
public class TestClient
  {
    public static void main (String[] argc)
      {
        if (argc.length != 1 && argc.length != 3)
          {
            System.out.println ("URL [count wait]\n" +
                                "  URL using standard setup: http://localhost:8080/spts-extservice\n"+
                                "  count is 1 if not given\n" +
                                "  wait is given in millseconds");
            System.exit (3);
          }
        try
          {
            HTTPSWrapper wrapper = new HTTPSWrapper ();
            long wait = 0;
            int count = 1;
            if (argc.length > 1)
              {
                count = Integer.parseInt (argc[1]);
                wait = Long.parseLong (argc[2]);
              }
            while (count-- > 0)
              {
                wrapper.setHeader ("Content-Type", "application/x-www-form-urlencoded");
                wrapper.makePostRequestUTF8 (argc[0], "X=5.5&Y=0.45");
                System.out.println (wrapper.getDataUTF8 ());
                Thread.sleep (wait);
              }
          }
        catch (Exception e)
          {
            e.printStackTrace ();
          }
      }
  }
