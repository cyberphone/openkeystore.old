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
package org.webpki.webapps.json.jcs;

import java.io.IOException;

import java.util.Date;

import org.webpki.json.JSONObjectWriter;

import org.webpki.json.test.Sign;

/**
 * Simple signature test generator
 */
public class MySignature
  {
    static enum ACTION {SYM, EC, RSA, X509};
    
    ACTION action;
    String data_to_be_signed;

    public MySignature (ACTION action, String data_to_be_signed)
      {
        this.action = action;
        this.data_to_be_signed = data_to_be_signed; 
      }
    
    public void writeJSONData (JSONObjectWriter wr) throws IOException
      {
        wr.setDateTime ("Now", new Date ());
        wr.setString ("MyData", data_to_be_signed);
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
      }
  }
