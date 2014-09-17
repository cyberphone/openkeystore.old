package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.util.Date;

import org.webpki.crypto.KeyStoreSigner;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONX509Signer;

public class PaymentRequest extends JSONProperties
  {
    String common_name;
    int amount;
    Currencies currency;
    String reference_id;
    Date date_time;
    
    public PaymentRequest (int amount)
      {
        this.amount = amount;
        this.currency = Currencies.USD;
        this.reference_id = "#" + CheckoutServlet.next_reference_id++;
        this.date_time = new Date ();
        this.common_name = MerchantServlet.COMMON_NAME;
      }

    private PaymentRequest ()
      {
      }

    public JSONObjectWriter serialize () throws IOException
      {
        JSONObjectWriter writer = new JSONObjectWriter ();
        writer.setString (COMMON_NAME_JSON, common_name);
        writer.setInt (AMOUNT_JSON, amount);
        writer.setString (CURRENCY_JSON, currency.toString ());
        writer.setString (REFERENCE_ID_JSON, reference_id);
        writer.setDateTime (DATE_TIME_JSON, date_time, true);
        KeyStoreSigner signer = new KeyStoreSigner (Init.merchant_eecert, null);
        signer.setExtendedCertPath (true);
        signer.setKey (null, Init.key_password);
        writer.setSignature (new JSONX509Signer (signer).setSignatureCertificateAttributes (true));
        return writer;
      }

    public static PaymentRequest parseJSONData (JSONObjectReader payee) throws IOException
      {
        PaymentRequest payment_request = new PaymentRequest ();
        payment_request.common_name = payee.getString (COMMON_NAME_JSON);
        payment_request.amount = payee.getInt (AMOUNT_JSON);
        payment_request.currency = Currencies.valueOf (payee.getString (CURRENCY_JSON));
        payment_request.reference_id = payee.getString (REFERENCE_ID_JSON);
        payment_request.date_time = payee.getDateTime (DATE_TIME_JSON).getTime ();
        return payment_request;
      }
  }
