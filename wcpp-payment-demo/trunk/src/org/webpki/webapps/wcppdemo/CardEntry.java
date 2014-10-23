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

import java.io.Serializable;

public class CardEntry implements Serializable
  {
    private static final long serialVersionUID = 1L;

    static final String CARD_LIST = "CardList";
    
    static final String PIN_FIELD  = "PIN";
    static final String USER_FIELD = "USER";
    
    static final String DEFAULT_PIN = "1234";
    static final String DEFAULT_USER = "No name defined!";

    static final int CARD_WIDTH      = 150;
    static final int CARD_HEIGHT     = 80;
    
    static final String CARD_DIV     = "<div style=\"padding:0px;margin-left:auto;margin-right:auto;width:" +
                                       CardEntry.CARD_WIDTH + "px;height:" +
                                       CardEntry.CARD_HEIGHT +
                                       "px;border-radius:8px;border-width:1px;border-style:solid;" +
                                       "border-color:#B0B0B0;box-shadow:3px 3px 3px #D0D0D0;" +
                                       "background-image:url('data:image/png;base64,";

    CardTypes card_type;
    String pin;
    String pan;
    String base64_image;
    String authorization_url;
    String user;
    JWK bank_encryption_key;
    JWK client_key;        
    String client_certificate;   // Base64URL (X.509)
    String cert_data;            // JCS SignatureCertificate {}
    boolean active;
  }
