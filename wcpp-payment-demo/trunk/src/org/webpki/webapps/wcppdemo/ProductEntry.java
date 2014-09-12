package org.webpki.webapps.wcppdemo;

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
