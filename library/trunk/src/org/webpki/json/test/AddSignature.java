/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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
package org.webpki.json.test;

import java.io.IOException;

import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ArrayUtil;

/**
 * Simple signature test generator
 */
public class AddSignature
  {
    static
      {
        Sign.installOptionalBCProvider ();
      }

    static enum ACTION {SYM, EC, RSA, X509};
    
    
    byte[] sign (JSONObjectWriter wr, ACTION action, boolean contain) throws IOException
      {
        if (contain)
          {
            wr = wr.createContainerObject ("Container");
          }
        if (action == ACTION.X509)
          {
            Sign.createX509Signature (wr);
          }
        else if (action == ACTION.SYM)
          {
            Sign.createSymmetricKeySignature (wr);
          }
        else
          {
            Sign.createAsymmetricKeySignature (wr, action == ACTION.RSA);
          }
        return wr.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT);
      }
    
    static void show ()
      {
        System.out.println (ACTION.SYM.toString () + "|" + ACTION.EC.toString () + "|" + ACTION.RSA.toString () + "|" + ACTION.X509.toString () + " contain(true|false) input-file\n");
        System.exit (0);
      }

    public static void main (String[] argc)
      {
        if (argc.length != 3)
          {
            show ();
          }
        for (ACTION action : ACTION.values ())
          {
            if (action.toString ().equalsIgnoreCase (argc[0]))
              {
                try
                  {
                    System.out.println (new String (new AddSignature ().sign (new JSONObjectWriter (JSONParser.parse (ArrayUtil.readFile (argc[2]))), action, new Boolean (argc[1])), "UTF-8"));
                  }
                catch (Exception e)
                  {
                    e.printStackTrace ();
                  }
                return;
              }
          }
        show ();
      }
  }
