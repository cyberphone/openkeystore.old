package org.webpki.keygen2.test;

import java.math.BigInteger;

import java.util.Date;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;

import org.webpki.crypto.test.ECKeys;

import org.webpki.keygen2.ProvisioningSessionRequestEncoder;
import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.PassphraseFormats;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.InputMethods;
import org.webpki.keygen2.PatternRestrictions;

public class provsessreq_enc
  {

    private static void show ()
      {
        System.out.println ("provsessreq_enc out_file\n");
        System.exit (3);
      }

    static ProvisioningSessionRequestEncoder create () throws Exception
      {
        Date server_time = DOMReaderHelper.parseDateTime (Constants.SERVER_TIME).getTime ();


        ProvisioningSessionRequestEncoder kre =
                    new ProvisioningSessionRequestEncoder (ECKeys.PUBLIC_KEY1,
                                                           Constants.REQUEST_ID,
                                                           "https://ca.example.com/keygenres",
                                                           100000,
                                                           10);
        kre.setServerTime (server_time);
        return kre;

       }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();

        ArrayUtil.writeFile (args[0], create ().writeXML());
      }
  }
