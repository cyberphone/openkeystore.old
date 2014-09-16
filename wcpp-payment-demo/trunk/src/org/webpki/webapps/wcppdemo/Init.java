package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import java.security.KeyStore;

import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.webpki.crypto.KeyStoreReader;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;

import org.webpki.webutil.InitPropertyReader;

public class Init implements ServletContextListener
  {
    static Logger logger = Logger.getLogger (Init.class.getName ());
    
    static String bank_url;
    static String merchant_url;
    static boolean web_crypto;
    
    static String cross_data_uri;
    static String working_data_uri;
    
    static String card_font;
    
    static KeyStore bank_eecert;

    private String getDataURI (String main, String extension) throws IOException
      {
        byte[] image = ArrayUtil.getByteArrayFromInputStream (Init.class.getResourceAsStream (main + "." + extension));
        return "data:image/" + extension + ";base64," + new Base64 (false).getBase64StringFromBinary (image);
      }

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
            web_crypto = properties.getPropertyBoolean ("web_crypto");
            cross_data_uri = getDataURI ("cross", "png");
            working_data_uri = getDataURI ("working", "gif");
            card_font = properties.getPropertyString ("card_font");
            bank_eecert = KeyStoreReader.loadKeyStore (Init.class.getResourceAsStream (properties.getPropertyString ("bank_eecert")), "testing");
            logger.info ("WebCrypto++ Payment Demo - " + (web_crypto ? "WebCrypto ": "Standard") + " Mode Successfully Initiated");
          }
        catch (IOException e)
          {
            logger.info("********\n" + e.getMessage() + "\n********");
            throw new RuntimeException (e);
          }
      }
  }
