package org.webpki.webapps.json.jcs;

import java.security.Security;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Init implements ServletContextListener
  {
    private static final long serialVersionUID = 1L;

    @Override
    public void contextDestroyed (ServletContextEvent event)
      {
      }

    @Override
    public void contextInitialized (ServletContextEvent event)
      {
        Security.insertProviderAt (new BouncyCastleProvider(), 1);
      }
  }
