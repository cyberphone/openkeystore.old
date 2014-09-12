package org.webpki.webapps.wcppdemo;

import java.io.Serializable;

import java.util.LinkedHashMap;

public class SavedShoppingCart implements Serializable
{
  private static final long serialVersionUID = 1L;

  static final String SAVED_SHOPPING_CART          = "SSD";

  int total;
  LinkedHashMap<String, Integer> items = new LinkedHashMap<String, Integer> ();
}

