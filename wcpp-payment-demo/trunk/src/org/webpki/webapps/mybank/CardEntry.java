package org.webpki.webapps.mybank;

import java.io.Serializable;

public class CardEntry implements Serializable
  {
	private static final long serialVersionUID = 1L;

	static final String CARD_LIST = "CardList";
	
	static final String PIN_FIELD  = "PIN";
	static final String USER_FIELD = "USER";
	
	static final String DEFAULT_PIN = "1234";
	static final String DEFAULT_USER = "No name defined!";

    String base64_image;
    String user;
    String pin;
    CardTypes card_type;
    boolean active;
  }
