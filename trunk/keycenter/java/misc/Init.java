package misc;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import java.util.HashMap;

import javax.servlet.ServletContextListener;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContext;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionListener;
import javax.servlet.http.HttpSessionEvent;

import org.webpki.keygen2.KeyOperationResponseDecoder;
import org.webpki.keygen2.KeyOperationRequestDecoder;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.jce.KeyStoreDatabaseConnection;
import org.webpki.jce.KeyUtil;

import admin.AdminSetAvailability;

import phone.PhoneWinServlet;


public class Init implements ServletContextListener, HttpSessionListener, KeyStoreDatabaseConnection
  {

    static class Message extends Thread
      {
        String recepient_email;
        String sender;
        String message;

        Message (String recepient_email,
                 String sender,
                 String message)
          {
            this.recepient_email = recepient_email;
            this.sender = sender;
            this.message = message;
          }

        public void run ()
          {
            try
              {
                sleep (10000);
                Connection conn = ProtectedServlet.getDatabaseConnection ();
                CallableStatement stmt = conn.prepareCall ("{call SetEmailMessageSP(?, ?, ?, ?)}");
                stmt.setString (1, recepient_email);
                stmt.setString (2, sender);
                stmt.setString (3, message);
                stmt.registerOutParameter (4, java.sql.Types.INTEGER);
                stmt.execute ();
                int user_id = stmt.getInt (4);
                stmt.close ();
                conn.close ();
                kickUser (user_id);
              }
            catch (Exception e)
              {
              }
          }
      }

    static HashMap<String,HttpSession> active_clients = new HashMap<String,HttpSession> ();

    public static void kickUser (int user_id) throws IOException
      {
        synchronized (active_clients)
          {
            for (HttpSession session : active_clients.values ().toArray (new HttpSession[0]))
              {
                synchronized (session)
                  {
                    if (ProtectedServlet.getUserID (session) == user_id)
                      {
                        phone.PhoneAJAXHandler.notifyData (session);
                      }
                  }
              }
          }
      }


    public static void sendPhoneMail (String recepient_email,
                                      String sender,
                                      String message)
      {
        new Message (recepient_email, sender, message).start ();
      }


    public Connection getDatabaseConnection () throws SQLException
      {
        return ProtectedServlet.getDatabaseConnection ();
      }

    public void contextInitialized (ServletContextEvent event)
      {
        ServletContext context = event.getServletContext ();
        try
          {
            XMLSchemaCache schema_cache = new XMLSchemaCache ();
            context.setAttribute (ProtectedServlet.APP_SCOPE, schema_cache);
            schema_cache.addWrapper (KeyOperationResponseDecoder.class);
            schema_cache.addWrapper (KeyOperationRequestDecoder.class);

            ProtectedServlet.initDatabaseParameters (context);

            KeyUtil.key_store_database_connection = this;
            PhoneWinServlet.initPhone (context);

            System.out.println ("Database started: " + AdminSetAvailability.resetServer ());
          }
        catch (Exception e)
          { 
            System.out.println (e.toString ());
            e.printStackTrace();
          } 
      }


    public void contextDestroyed (ServletContextEvent event)
      {
      }


    public void sessionCreated (HttpSessionEvent se)
      {
        HttpSession session = se.getSession ();
        synchronized (active_clients)
          {
            active_clients.put (session.getId (), session);
          }
      }


    public void sessionDestroyed (HttpSessionEvent se)
      {
        try
          {
            HttpSession session = se.getSession ();
            synchronized (session)
              {
                phone.PhoneAJAXHandler.notifyData (session);
              }
            synchronized (active_clients)
              {
                active_clients.remove (session.getId ());
              }
          }
        catch (IOException e)
          {
            System.out.println (e.toString ());
            e.printStackTrace();
          }
      }

  }
