package org.webpki.webapps.wcppdemo;

public enum Currencies
  {
    USD ("$\\u200a",       true), 
    EUR ("\\u200a\\u20ac", false),
    GBP ("£\\u200a",       true);
    
    String symbol;
    boolean first_position;
    
    Currencies (String symbol, boolean first_position)
      {
        this.symbol = symbol;
        this.first_position = first_position;
      }
  }
