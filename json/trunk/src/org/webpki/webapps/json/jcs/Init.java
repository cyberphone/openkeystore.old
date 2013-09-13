package org.webpki.webapps.json.jcs;

import java.security.Provider;
import java.security.Security;

import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class Init implements ServletContextListener
  {
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger (Init.class.getName ());

    StringBuffer info_string;
    
    int info_lengthp2;
    
    void printHeader ()
      {
        for (int i = 0; i < info_lengthp2; i++)
          {
            info_string.append ('=');
          }
        info_string.append ('\n');
      }
    
    void printInfo (String info)
      {
        info_string = new StringBuffer ("\n\n");
        info_lengthp2 = info.length () + 4;
        printHeader ();
        info_string.append ("= ").append (info).append (" =\n");
        printHeader ();
        logger.info (info_string.toString ());
      }

    void installOptionalBCProvider ()
      {
        @SuppressWarnings("rawtypes")
        Class bc = null;
        try
          {
            bc = Class.forName ("org.bouncycastle.jce.provider.BouncyCastleProvider");
          }
        catch (ClassNotFoundException e)
          {
            printInfo ("BouncyCastle provider not in path - Using the platform provider");
            return;
          }
        try
          {
            Security.insertProviderAt ((Provider) bc.newInstance (), 1);
            printInfo ("Installed BouncyCastle as first provider");
          }
        catch (Exception e)
          {
            printInfo ("Failed to install BouncyCastle!");
          }
      }

    @Override
    public void contextDestroyed (ServletContextEvent event)
      {
      }

    @Override
    public void contextInitialized (ServletContextEvent event)
      {
        installOptionalBCProvider ();
      }
  }
