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

import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONEnvelopedSignatureDecoder;
import org.webpki.json.JSONReaderHelper;

/**
 * Simple verify program
 */
public class Verify extends JSONDecoder
  {
    
    public static void main (String[] argc)
      {
/*
        try
          {
            System.out.println (new String (new Verify ().getJSONData (), "UTF-8"));
          }
        catch (IOException e)
          {
            e.printStackTrace ();
          }
*/
      }

    @Override
    protected void unmarshallJSONData (JSONReaderHelper rd) throws IOException
      {
        recurse (rd, true);
      }

    void recurse (JSONReaderHelper rd, boolean ignore) throws IOException
      {
        for (String property : rd.getProperties ())
          {
            if (ignore)
              {
                ignore = false;
                continue;
              }
            switch (rd.getPropertyType (property))
              {
                case OBJECT:
                  if (property.equals (JSONEnvelopedSignatureDecoder.ENVELOPED_SIGNATURE_JSON))
                    {
                      JSONEnvelopedSignatureDecoder signature = new JSONEnvelopedSignatureDecoder (rd);
                    }
                  else
                    {
                      recurse (rd.getObject (property), false);
                    }
                  break;

                case OBJECT_ARRAY:
                  for (JSONReaderHelper next : rd.getObjectArray (property))
                    {
                      recurse (next, false);
                    }
                  break;

                default:
                  rd.scanAway (property);
              }
          }
      }

    @Override
    protected String getVersion ()
      {
        return Sign.VERSION;
      }

    @Override
    protected String getRootProperty ()
      {
        return Sign.ROOT_PROPERTY;
      }
  }
