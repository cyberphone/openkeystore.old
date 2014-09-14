package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import java.util.Date;

import org.webpki.crypto.KeyStoreSigner;

import org.webpki.crypto.test.DemoKeyStore;

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

   public JSONObjectWriter serialize () throws IOException
      {
        JSONObjectWriter writer = new JSONObjectWriter ();
        writer.setString (COMMON_NAME_JSON, common_name);
        writer.setInt (AMOUNT_JSON, amount);
        writer.setString (CURRENCY_JSON, currency.toString ());
        writer.setString (REFERENCE_ID_JSON, reference_id);
        writer.setDateTime (DATE_TIME_JSON, date_time, true);
        KeyStoreSigner signer = new KeyStoreSigner (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer.setExtendedCertPath (true);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        writer.setSignature (new JSONX509Signer (signer).setSignatureCertificateAttributes (true));
        return writer;
      }
  }
