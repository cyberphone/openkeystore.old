package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.webpki.webutil.InitPropertyReader;

public class Init implements ServletContextListener
  {
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger (Init.class.getName ());
    
    static String bank_url;
    static String merchant_url;

    @Override
    public void contextDestroyed (ServletContextEvent event)
      {
      }

    @Override
    public void contextInitialized (ServletContextEvent event)
      {
    	InitPropertyReader properties = new InitPropertyReader ();
    	properties.initProperties (event);
    	try 
    	  {
			bank_url = properties.getPropertyString ("bank_url");
		    merchant_url = properties.getPropertyString ("merchant_url");
		  }
    	catch (IOException e)
    	  {
    	    logger.info("********\n" + e.getMessage() + "\n********");
    		throw new RuntimeException (e);
    	  }
      }
  }
