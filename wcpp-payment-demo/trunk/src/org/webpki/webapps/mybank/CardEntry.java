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

    static final int CARD_WIDTH      = 150;
    static final int CARD_HEIGHT     = 80;
    
    static final String CARD_DIV_1   = "<div title=\"PAN=";
    static final String CARD_DIV_2   = "\" style=\"padding:0px;margin-left:auto;margin-right:auto;width:" +
                                       CardEntry.CARD_WIDTH + "px;height:" +
                                       CardEntry.CARD_HEIGHT +
                                       "px;border-radius:8px;border-width:1px;border-style:solid;" +
                                       "border-color:#B0B0B0;box-shadow:3px 3px 3px #D0D0D0;" +
                                       "background-image:url('data:image/png;base64,";

    String base64_image;
    String pan;
    String user;
    String pin;
    CardTypes card_type;
    boolean active;
  }
