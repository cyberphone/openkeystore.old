/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;

public enum Messages
  {
    INITIALIZE           ("Initialize"),
    INVOKE               ("Invoke"),
    ABORT                ("Abort"),
    AUTHORIZE            ("Authorize"),
    TRANSACTION_REQUEST  ("TransactionRequest"),
    TRANSACTION_RESPONSE ("TransactionResponse");
    
    String json_name;
    
    Messages (String json_name)
      {
        this.json_name = json_name;
      }

    @Override
    public String toString ()
      {
        return json_name;
      }

    public static JSONObjectWriter createBaseMessage (Messages message) throws IOException
      {
        return new JSONObjectWriter ()
                     .setString (JSONDecoderCache.CONTEXT_JSON, BaseProperties.WCPP_DEMO_CONTEXT_URI)
                     .setString (JSONDecoderCache.QUALIFIER_JSON, message.toString ());
      }
  
    public static JSONObjectReader parseBaseMessage (Messages expected_message, JSONObjectReader request_object) throws IOException
      {
        if (!request_object.getString (JSONDecoderCache.CONTEXT_JSON).equals (BaseProperties.WCPP_DEMO_CONTEXT_URI))
          {
            throw new IOException ("Unknown context: " + request_object.getString (JSONDecoderCache.CONTEXT_JSON));
          }
        if (!request_object.getString (JSONDecoderCache.QUALIFIER_JSON).equals (expected_message.toString ()))
          {
            throw new IOException ("Unexpected qualifier: " + request_object.getString (JSONDecoderCache.QUALIFIER_JSON));
          } 
        return request_object;
      }
  }
