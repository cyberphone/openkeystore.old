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
package org.webpki.webapps.wcpppaymentdemo;

import java.io.Serializable;

public class ProductEntry implements Serializable
  {
    private static final long serialVersionUID = 1L;

    String image_url;
    String name;
    int price_mult_100;
    
    public ProductEntry (String image_url, String name, int price_mult_100)
      {
        this.image_url = image_url;
        this.name = name;
        this.price_mult_100 = price_mult_100;
      }
  }
