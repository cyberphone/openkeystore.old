package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

public class JSONProperties
  {
    static final String PAYMENT_REQUEST_JSON       = "PaymentRequest";
    static final String AMOUNT_JSON                = "Amount";
    static final String ERROR_JSON                 = "Error";
    static final String CURRENCY_JSON              = "Currency";
    static final String DATE_TIME_JSON             = "DateTime";
    static final String TRANSACTION_ID_JSON        = "TransactionID";
    static final String REFERENCE_ID_JSON          = "ReferenceID";
    static final String COMMON_NAME_JSON           = "CommonName";
    static final String CARD_TYPES_JSON            = "CardTypes";
    static final String AUTHORIZATION_URL_JSON     = "AuthorizationURL";  // URL to payment provider
    static final String PAN_JSON                   = "PAN";               // Card number
    static final String CARD_TYPE_JSON             = "CardType";          // Card type
    static final String PAYEE_PAN_JSON             = "PayeePAN";          // Card number given to merchant
    static final String REQUEST_HASH_JSON          = "RequestHash";
    static final String DOMAIN_NAME_JSON           = "DomainName";
    
    static final String WCPP_DEMO_CONTEXT_URI      = "http://xmlns.webpki.org/wcpp-payment-demo";
    
    public static JSONObjectWriter createJSONBaseObject (Messages message) throws IOException
      {
        JSONObjectWriter writer = new JSONObjectWriter ();
        writer.setString (JSONDecoderCache.CONTEXT_JSON, WCPP_DEMO_CONTEXT_URI);
        writer.setString (JSONDecoderCache.QUALIFIER_JSON, message.toString ());
        return writer;
      }
    
    public static JSONObjectReader parsePaymentMessage (Messages message, byte[] raw_data) throws IOException
      {
        JSONObjectReader json = JSONParser.parse (raw_data);
        if (!json.getString (JSONDecoderCache.CONTEXT_JSON).equals (WCPP_DEMO_CONTEXT_URI))
          {
            throw new IOException ("Unknown context: " + json.getString (JSONDecoderCache.CONTEXT_JSON));
          }
        if (!json.getString (JSONDecoderCache.QUALIFIER_JSON).equals (message.toString ()))
          {
            throw new IOException ("Unexpected qualifier: " + json.getString (JSONDecoderCache.QUALIFIER_JSON));
          } 
        return json;
      }
  }
