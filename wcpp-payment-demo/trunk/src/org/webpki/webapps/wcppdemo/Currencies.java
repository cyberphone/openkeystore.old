package org.webpki.webapps.wcppdemo;

public enum Currencies
  {
    USD ("$",       true), 
    EUR ("\\u20ac", false),
    GBP ("£",       true);
    
    String symbol;
    boolean first_position;
    
    Currencies (String symbol, boolean first_position)
      {
        this.symbol = symbol;
        this.first_position = first_position;
      }
  }
