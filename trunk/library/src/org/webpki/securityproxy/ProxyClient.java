/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.securityproxy;

import java.io.IOException;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;

import java.util.Vector;

import java.util.logging.Level;
import java.util.logging.Logger;

import java.net.HttpURLConnection;
import java.net.URL;
import java.net.Proxy;
import java.net.InetSocketAddress;
import java.net.InetAddress;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.webpki.crypto.KeyStoreReader;

/**
 * Security proxy local service (client).
 */
public class ProxyClient
  {
    private static Logger logger = Logger.getLogger (ProxyClient.class.getCanonicalName ());
    
    private ProxyRequestHandler request_handler;
    
    /**
     * Creates an empty security proxy.
     * @see #initProxy
     * 
     * @param request_handler the proxy user's interface
     */
    public ProxyClient (ProxyRequestHandler request_handler)
      {
        this.request_handler = request_handler;
      }

    private class ProxyChannel implements Runnable
      {
        ////////////////////////////////////
        // Instance variables
        ////////////////////////////////////
        long channel_id;

        InternalClientObject send_object;

        boolean hanging;

        boolean running = true;

        private void badReturn (String what)
          {
            if (running)
              {
                logger.severe ("Channel[" + channel_id + "] returned: " + what);
              }
          }

        public void run ()
          {
            int error_count = 0;
            if (debug)
              {
                logger.info ("Channel[" + channel_id + "] started");
              }
            while (running)
              {
                boolean throwed_an_iox = true;
                HttpURLConnection conn = null;
                try
                  {
                    ////////////////////////////////////////////////////////////////////////////////////
                    // This how the proxy client starts its work-day, by launching a call to
                    // the proxy server. Usually the call contains nothing but sometimes
                    // there is a response from the local service included. The very first call
                    // contains a "master reset" which clears any resuidal objects in the server
                    // which may be left after a network or client proxy error.
                    ////////////////////////////////////////////////////////////////////////////////////
                    conn = (proxy == null) ? (HttpURLConnection) new URL (proxy_url).openConnection () : (HttpURLConnection) new URL (proxy_url).openConnection (proxy);

                    if (socket_factory != null)
                      {
                        ((HttpsURLConnection) conn).setSSLSocketFactory (socket_factory);
                      }

                    if (send_object instanceof InternalIdleObject)
                      {
                        synchronized (upload_objects)
                          {
                            if (!upload_objects.isEmpty ())
                              {
                                send_object = upload_objects.remove (0);
                                if (debug)
                                  {
                                    logger.info ("Upload client");
                                  }
                              }
                          }
                      }

                    ////////////////////////////////////////////////////////////////////////
                    // The following only occurs if there is some kind of network problem
                    ////////////////////////////////////////////////////////////////////////
                    conn.setReadTimeout ((cycle_time * 3) / 2 + 30000);

                    ////////////////////////////////////////////////////////////////////////
                    // Serialize the data object to send (Conf, Idle, Response)
                    ////////////////////////////////////////////////////////////////////////
                    byte[] send_data = InternalObjectStream.writeObject (send_object);

                    ////////////////////////////////////////////////////////////////////////
                    // Write Serialized object
                    ////////////////////////////////////////////////////////////////////////
                    conn.setDoOutput (true);
                    OutputStream ostream = conn.getOutputStream ();
                    ostream.write (send_data);
                    ostream.flush ();
                    ostream.close ();

                    ///////////////////////////////////////////////////////////////////////
                    // Set the default object for the next round
                    ///////////////////////////////////////////////////////////////////////
                    send_object = idle_object;

                    ////////////////////////////////////////////////////////////////////////////////////
                    // This is where the proxy client spends most its time - Waiting for some action
                    ////////////////////////////////////////////////////////////////////////////////////
                    hanging = true;
                    BufferedInputStream istream = new BufferedInputStream (conn.getInputStream ());
                    ByteArrayOutputStream out = new ByteArrayOutputStream ();
                    byte[] temp = new byte[1024];
                    int len;
                    while ((len = istream.read (temp)) != -1)
                      {
                        out.write (temp, 0, len);
                      }
                    byte[] data = out.toByteArray ();
                    int status = conn.getResponseCode ();
                    if (status != HttpURLConnection.HTTP_OK)
                      {
                        throw new IOException ("Bad HTTP return:" + status);
                      }
                    istream.close ();
                    conn.disconnect ();
                    hanging = false;
                    throwed_an_iox = false;
                    if (data.length == 0)
                      {
                        //////////////////////////////////////////////////////
                        // No request data. See if it is time to just die..
                        //////////////////////////////////////////////////////
                        if (upload_objects.isEmpty ())
                          {
                            if (unneededProxy (channel_id))
                              {
                                if (debug)
                                  {
                                    logger.info ("Channel[" + channel_id + "] was deleted");
                                  }
                                return;
                              }
                            if (debug)
                              {
                                logger.info ("Channel[" + channel_id + "] continues");
                              }
                          }
                      }
                    else
                      {
                        /////////////////////////////////////////////////////////////////////////////////////
                        // We do have a request in progress. Check that we have enough workers in action
                        /////////////////////////////////////////////////////////////////////////////////////
                        checkForProxyDemand (false);

                        ////////////////////////////////////
                        // Read the request object
                        ////////////////////////////////////
                        InternalRequestObject request_object = (InternalRequestObject) InternalObjectStream.readObject (data, request_handler);

                        //////////////////////////////////////////////////////
                        // Now do the request/response to the local server
                        //////////////////////////////////////////////////////
                        send_object = new InternalResponseObject (request_handler.handleProxyRequest (request_object.proxy_request), request_object.caller_id, client_id);
                      }

                    /////////////////////////////////////////////////
                    // A round without errors. Reset error counter
                    /////////////////////////////////////////////////
                    error_count = 0;
                  }
                catch (ClassNotFoundException cnfe)
                  {
                    badReturn ("Unexpected object!");
                  }
                catch (IOException ioe)
                  {
                    badReturn (ioe.getMessage ());
                    ioe.printStackTrace ();
                    try
                      {
                        if (throwed_an_iox && running)
                          {
                            String err = conn.getResponseMessage ();
                            if (err != null)
                              {
                                System.out.println (err);
                              }
                          }
                      }
                    catch (IOException ioe2)
                      {
                      }
                    if (running)
                      {
                        //////////////////////////////////////////////////
                        // Kill and remove all proxy channels (threads)
                        //////////////////////////////////////////////////
                        killProxy ();

                        if (++error_count == MAX_ERRORS)
                          {
                            ///////////////////////////
                            // We give up completely!
                            ///////////////////////////
                            logger.severe ("Hard error.  Shut down the proxy!");
                            return;
                          }

                        ///////////////////////////////////////////////////////////////////////
                        // It looks bad but we try restarting before shutting down the proxy
                        ///////////////////////////////////////////////////////////////////////
                        running = true;
                        send_object = server_configuration;
                        channels.add (this);
                        try
                          {
                            if (debug)
                              {
                                logger.info ("Channel[" + channel_id + "] resumes (after waiting " + retry_timeout/1000 + "s) for a new try...");
                              }
                            Thread.sleep (retry_timeout);
                          }
                        catch (InterruptedException ie)
                          {
                          }
                      }
                  }
                hanging = false;
              }
          }
      }

    ////////////////////////////////////
    // Configurables
    ////////////////////////////////////
    private String proxy_url;

    private Proxy proxy;

    private int max_workers;

    private int cycle_time;

    private int retry_timeout;

    private boolean debug;

    private KeyStore proxy_service_truststore;
    private KeyStore proxy_service_keystore;
    private String proxy_service_key_password;

    private SSLSocketFactory socket_factory;
    
    ////////////////////////////////////
    // App-wide "globals"
    ////////////////////////////////////
    private long last_channel_id;

    private String client_id;

    private InternalServerConfiguration server_configuration;

    private InternalIdleObject idle_object;

    private Vector<ProxyChannel> channels = new Vector<ProxyChannel> ();

    private Vector<InternalUploadObject> upload_objects = new Vector<InternalUploadObject> ();

    ////////////////////////////////////
    // Defaults
    ////////////////////////////////////
    private static final int REQUEST_TIMEOUT = 60 * 1000;

    private static final int MAX_ERRORS = 1000;

    private void prepareForSSL ()
      {
        if (proxy_url.startsWith ("https:") && (proxy_service_truststore != null || proxy_service_keystore != null))
          {
            try
              {
                TrustManager[] trust_managers = null;
                KeyManager[] key_managers = null;
                if (proxy_service_keystore != null)
                  {
                    KeyManagerFactory kmf = KeyManagerFactory.getInstance ("SunX509");
                    kmf.init (proxy_service_keystore, proxy_service_key_password.toCharArray ());
                    key_managers = kmf.getKeyManagers ();
                  }
                if (proxy_service_truststore != null)
                  {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance ("SunX509");
                    tmf.init (proxy_service_truststore);
                    trust_managers = tmf.getTrustManagers ();
                  }
                SSLContext ssl_context = SSLContext.getInstance ("TLS");
                ssl_context.init (key_managers, trust_managers, null);
                socket_factory =  ssl_context.getSocketFactory ();
              }
            catch (GeneralSecurityException gse)
              {
                logger.log (Level.SEVERE, "SSL setup issues", gse);
              }
          }
      }

    private static char hex (int i)
      {
        if (i < 10)
          {
            return (char) (i + 48);
          }
        return (char) (i + 55);
      }

    static String toHexString (byte indata[])
      {
        StringBuffer res = new StringBuffer ();
        int i = 0;
        while (i < indata.length)
          {
            int v = indata[i++] & 0xFF;
            res.append (hex (v / 16));
            res.append (hex (v % 16));
          }
        return res.toString ();
      }

    private void spawnProxy ()
      {
        synchronized (channels)
          {
            ProxyChannel channel = new ProxyChannel ();
            channel.channel_id = last_channel_id++;

            /////////////////////////////////////////////////////////////////////////////////////////
            // If it is the first channel - issue a master reset + configuration to the proxy server
            /////////////////////////////////////////////////////////////////////////////////////////
            if (channel.channel_id == 0)
              {
                byte[] cid = new byte[10];
                new SecureRandom ().nextBytes (cid);
                client_id = toHexString (cid);

                server_configuration = new InternalServerConfiguration (cycle_time, REQUEST_TIMEOUT, REQUEST_TIMEOUT, client_id, debug);
                idle_object = new InternalIdleObject (client_id);
                channel.send_object = server_configuration;
                if (debug)
                  {
                    logger.info ("Proxy " + client_id + " initiated");
                  }
              }
            else
              {
                channel.send_object = idle_object;
              }
            channels.add (channel);
            new Thread (channel).start ();
          }
      }

    private void checkForProxyDemand (boolean increase)
      {
        ////////////////////////////////////////////////////////////////////////////////
        // Check that there is ample of free channels in order to keep up with requests
        ////////////////////////////////////////////////////////////////////////////////
        synchronized (channels)
          {
            if (channels.size () < max_workers)
              {
                //////////////////////////////////////////
                // We have not yet reached the ceiling
                //////////////////////////////////////////
                int q = 0;
                for (ProxyChannel channel : channels)
                  {
                    if (channel.hanging) // = Most likely to be idle
                      {
                        q++;
                      }
                  }
                if (increase)
                  {
                    q -= 2;
                  }

                //////////////////////////////////////////
                // The margin checker
                //////////////////////////////////////////
                if (q < 2 || q < (max_workers / 5))
                  {
                    //////////////////////////////////////////
                    // We could use a helping hand here...
                    //////////////////////////////////////////
                    spawnProxy ();
                  }
              }
          }
      }

    private boolean unneededProxy (long test_channel_id) throws IOException
      {
        synchronized (channels)
          {
            if (channels.size () == 1)
              {
                //////////////////////////////////////////////
                // We must at least have one living thread...
                //////////////////////////////////////////////
                return false;
              }

            //////////////////////////////////////////////
            // Ooops. We are probably redundant...
            //////////////////////////////////////////////
            int q = 0;
            for (ProxyChannel channel : channels)
              {
                if (channel.channel_id == test_channel_id)
                  {
                    channels.remove (q);
                    return true;
                  }
                q++;
              }
            throw new IOException ("Internal error.  Missing channel_id: " + test_channel_id);
          }
      }

    /**
     * For HTTPS use this method as an alternative to the global truststore.
     *  
     * @param truststore
     * @param password
     * @throws IOException
     */
    public void setProxyServiceTruststore (String truststore, String password) throws IOException
      {
        checkOrder ();
        proxy_service_truststore = KeyStoreReader.loadKeyStore (truststore, password);
      }

    /**
     * For HTTPS client certificate authentication.
     * 
     * @param keystore
     * @param key_password
     * @throws IOException
     */
    public void setProxyServiceClientKey (String keystore, String key_password) throws IOException
      {
        checkOrder ();
        proxy_service_keystore = KeyStoreReader.loadKeyStore (keystore, key_password);
        proxy_service_key_password = key_password;
      }

    /**
     * Sets HTTP web-proxy parameters. This method needs to be called for usage
     * of the security proxy scheme where local LAN rules require outbound HTTP
     * calls to through a web-proxy server.
     * <p>
     * Note: <i>The proxy scheme does currently not support web-proxy authentication.</i>
     *
     * @param address
     *          The host name or IP address of the web-proxy server.
     * @param port
     *          The TCP port number to use.
     */
    public void setWebProxy (String address, int port) throws IOException
      {
        checkOrder ();
        proxy = new Proxy (Proxy.Type.HTTP, new InetSocketAddress (InetAddress.getByName (address), port));
      }

    private void checkOrder () throws IOException
      {
        if (proxy_url != null)
          {
            throw new IOException ("This method must be called before initProxy!");
          }
      }

    /**
     * Terminates and clears the proxy connection(s).
     * A well-behaved client service should call this before terminating.
     */
    public void killProxy ()
      {
        synchronized (channels)
          {
            while (!channels.isEmpty ())
              {
                ProxyChannel channel = channels.remove (0);
                channel.running = false;
                if (debug)
                  {
                    logger.info ("Channel[" + channel.channel_id + "] was relased");
                  }
              }
          }
        upload_objects.clear ();
      }

    /**
     * Sets proxy core parameters and initializes the proxy channel.
     * <p>
     *
     * @see #setProxyServiceTruststore
     * @see #setProxyServiceClientKey
     * 
     * @param proxy_url
     *          The URL to the proxy channel.
     * @param max_workers
     *          The maximum number of parallel proxy channels to use.
     * @param cycle_time
     *          The timeout in seconds for the &quot;waiting&quot; state.
     * @param retry_timeout
     *          The timeout in seconds for resuming operation after a failure.
     * @param debug
     *          Defines if debug output is to be created or not.
     */
    public void initProxy (String proxy_url, int max_workers, int cycle_time, int retry_timeout, boolean debug) throws IOException
      {
        killProxy ();
        last_channel_id = 0;
        this.proxy_url = proxy_url;
        this.max_workers = max_workers;
        this.cycle_time = cycle_time * 1000;
        this.retry_timeout = retry_timeout * 1000;
        this.debug = debug;
        prepareForSSL ();
        spawnProxy ();
      }
    
    /**
     * Put an object for upload in a queue.
     * @param upload_payload_object a derived object
     */
    public void addUploadObject (ProxyUploadInterface upload_payload_object)
      {
        synchronized (upload_objects)
          {
            try
              {
                upload_objects.add (new InternalUploadObject (client_id, upload_payload_object));
              }
            catch (IOException e)
              {
              }
          }
        checkForProxyDemand (true);
      }

  }
