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
package org.webpki.keygen2;

import static org.webpki.keygen2.KeyGen2Constants.*;

import java.io.IOException;

import org.webpki.json.JSONBaseHTML;

/**
 * Create an HTML description of the current KeyGen2 protocol.
 * 
 * @author Anders Rundgren
 */
public class KeyGen2HTMLReference
  {
    public static void main (String args[]) throws IOException
      {
        if (args.length != 1)
          {
            new RuntimeException ("Missing file argument");
          }
        JSONBaseHTML json = new JSONBaseHTML ();
        json.addProtocolTable (PROVISIONING_FINALIZATION_REQUEST_JSON)
          .newRow ()
          .newColumn ()
          .addQualifier (KEYGEN2_NS)
          .newColumn ()
          .newColumn ()
          .newRow ()
          .newColumn ()
          .addContext (PROVISIONING_FINALIZATION_REQUEST_JSON)
          .newColumn ()
          .newColumn ()
          .newRow ()
          .newColumn ()
          .addProperty (SERVER_SESSION_ID_JSON)
          .addSymbolicValue (SERVER_SESSION_ID_JSON)
          .newColumn ()
          .newColumn ()
          .newRow ()
          .newColumn ()
          .addProperty (ISSUED_CREDENTIALS_JSON)
          .addArrayLink (ISSUED_CREDENTIALS_JSON)
          .newColumn ()
          .setUsage (false, 1)
          .newColumn ();

        json.addSubItemTable (ISSUED_CREDENTIALS_JSON, true)
          .newRow ()
          .newColumn ()
          .addProperty (SERVER_SESSION_ID_JSON)
          .addSymbolicValue (SERVER_SESSION_ID_JSON)
          .newColumn ()
          .newColumn ()
          .newRow ()
          .newColumn ()
          .addProperty (ISSUED_CREDENTIALS_JSON)
          .addArrayLink (ISSUED_CREDENTIALS_JSON)
          .newColumn ()
          .setUsage (false, 1)
          .newColumn ();

        json.writeHTML (args[0]);
      }
  }
