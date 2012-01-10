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
package org.webpki.securityproxy.test.intextcommon;

import org.webpki.securityproxy.ProxyServer;

/**
 * Security proxy server singleton object.
 * 
 * Each proxy server channel usage MUST define such an object unless it
 * uses the same HTTP port for internal and external proxy operations.
 *
 */
public class IntExtCommon
  {
    static ProxyServer ps = new ProxyServer ();
    
    public static ProxyServer getProxy ()
      {
        return ps;
      }
  }
