package org.webpki.hlca;

import java.io.IOException;

import java.util.Vector;

import org.webpki.crypto.JKSCAVerifier;

import org.webpki.hlca.SecureKeyStore;
import org.webpki.infocard.InfoCardReader;


/**
 * Information Card provider.
 */
public class InformationCardProvider extends ExtensionProvider implements ExtensionConsumer
  {
    public static class InformationCard extends InfoCardReader
      {
        int user_id;

        int key_id;
        
        SecureKeyStore sks;

        boolean symmetric_key_flag;

        private InformationCard (byte[] data, SecureKeyStore sks, int key_id, boolean symmetric_key_flag) throws IOException
          {
            super (data, new JKSCAVerifier ());
            this.key_id = key_id;
            this.symmetric_key_flag = symmetric_key_flag;
          }
      }


    InformationCardProvider () // Only used by the framework 
      {
      }


    public void parse (byte[] data, KeyDescriptor key_descriptor) throws IOException
      {
        new InfoCardReader (data, new JKSCAVerifier ());
      }


    public String getName ()
      {
        return "Information Card 1.0";
      }


    public String getTypeURI ()
      {
        return "http://schemas.xmlsoap.org/ws/2005/05/identity";
      }


    public static InformationCard[] getInformationCards (SecureKeyStore sks) throws IOException
      {
        ExtensionProvider[] eps = ExtensionProvider.getExtensionProviders (sks,
                                                                           null,
                                                                           InformationCardProvider.class);
        if (eps == null)
          {
            return null;
          }
        Vector<InformationCard> cards = new Vector<InformationCard> ();
        for (ExtensionProvider ep : eps)
          {
            cards.add (new InformationCard (ep.extension.data, ep.sks, ep.key_id, ep.symmetric_key_flag));
          }
        return cards.toArray (new InformationCard[0]);
      }

  }
