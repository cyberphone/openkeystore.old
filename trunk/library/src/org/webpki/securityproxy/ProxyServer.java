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
import java.io.ByteArrayOutputStream;

import java.util.HashMap;
import java.util.Vector;

import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * Security proxy server core logic. Called by a proxy servlet application.
 */
public class ProxyServer
  {
    private static Logger logger = Logger.getLogger (ProxyServer.class.getName ());

    private static HashMap<String,ProxyServer> instances = new HashMap<String,ProxyServer> (); 

    private Vector<RequestDescriptor> response_queue = new Vector<RequestDescriptor> ();

    private Vector<RequestDescriptor> waiting_callers = new Vector<RequestDescriptor> ();
    
    private Vector<ProxyUploadHandler> upload_event_subscribers = new Vector<ProxyUploadHandler> ();

    private Vector<ProxyRequest> proxies = new Vector<ProxyRequest> ();

    private long next_caller_id;

    private long next_proxy_id;
    
    private String instance_name;  // Optional

    private InternalServerConfiguration server_configuration;

    private ProxyRequestInterface last_request;

    private int response_timeout_errors;

    private int request_timeout_errors;
    
    private Class<? extends ProxyServerErrorFactory> error_container;
    
    public static ProxyServer getInstance (String name_of_instance)
      {
        synchronized (instances)
          {
            ProxyServer instance = instances.get (name_of_instance);
            if (instance == null)
              {
                instances.put (name_of_instance, instance = new ProxyServer ());
                instance.instance_name = name_of_instance;
              }
            return instance;
          }
      }
    
    public void setProxyServerErrorFactory (Class<? extends ProxyServerErrorFactory> error_container)
      {
        this.error_container = error_container;
      }
    
    public synchronized void addUploadEventHandler (ProxyUploadHandler ueh)
      {
        upload_event_subscribers.add (ueh);
      }
    
    public synchronized void deleteUploadEventHandler (ProxyUploadHandler ueh)
      {
        upload_event_subscribers.remove (ueh);
      }
    
    public synchronized boolean isReady ()
      {
        return server_configuration != null;
      }

    private class Synchronizer
      {

        boolean touched;
        boolean timeout_flag;

        synchronized boolean perform (int timeout)
          {
            while (!touched && !timeout_flag)
              {
                try
                  {
                    wait (timeout);
                  }
                catch (InterruptedException e)
                  {
                    return false;
                  }
                timeout_flag = true;
              }
            return touched;
          }

        synchronized void haveData4You ()
          {
            touched = true;
            notify ();
          }
      }

    private abstract class Caller
      {
        abstract boolean transactRequest () throws IOException, ServletException;

        abstract void transactResponse () throws IOException, ServletException;

        abstract void transactProxy () throws IOException, ServletException;
      }

    private class RequestDescriptor extends Caller
      {
        HttpServletResponse response;
        InternalRequestObject request_object;
        InternalResponseObject response_object;
        ProxyRequest proxy;
        Synchronizer request_waiter = new Synchronizer ();
        Synchronizer response_waiter = new Synchronizer ();

        void setProxyWorker (ProxyRequest proxy)
          {
            this.proxy = proxy;
            this.proxy.request_descriptor = this;
          }

        boolean transactRequest () throws IOException, ServletException
          {
            //////////////////////////////////////////////////
            // No proxy available, wait for one (or die)...
            //////////////////////////////////////////////////
            if (request_waiter.perform (server_configuration.request_timeout))
              {
                return true;
              }
            else
              {
                request_timeout_errors++;
                cleanUpAfterFailedCall (this, "Call request timeout");
                return false;
              }
          }

        void transactProxy () throws IOException, ServletException
          {
            ////////////////////////////////////////////////////////////////
            // We have a request and a now freed proxy.
            ////////////////////////////////////////////////////////////////
            request_waiter.haveData4You (); // Get out of the hanging
            proxy.proxy_worker.haveData4You (); // Proxy: just do it!
            proxy.transactProxy ();
          }

        void transactResponse () throws IOException, ServletException
          {
            if (response_waiter.perform (server_configuration.response_timeout))
              {
                //////////////////////////////////////////
                // Normal response, output HTTP headers
                //////////////////////////////////////////
                response.setContentLength (response_object.response_data.data.length);
                response.setContentType (response_object.response_data.mime_type);
                for (String name : response_object.response_data.headers.keySet ())
                  {
                    response.setHeader (name, response_object.response_data.headers.get (name));
                  }
                response.getOutputStream ().write (response_object.response_data.data);
              }
            else
              {
                response_timeout_errors++;
                cleanUpAfterFailedCall (this, "Call response timeout");
              }
          }
      }

    private class ProxyRequest extends Caller
      {
        HttpServletResponse proxy_response;
        long proxy_id;
        Synchronizer proxy_worker = new Synchronizer ();
        RequestDescriptor request_descriptor;

        void setCaller (RequestDescriptor request_descriptor)
          {
            this.request_descriptor = request_descriptor;
          }

        boolean transactRequest () throws IOException, ServletException
          {
            //////////////////////////////////////////////////////////
            // We had a free proxy to serve the request in question!
            //////////////////////////////////////////////////////////
            proxy_worker.haveData4You (); // Proxy: just do it!
            return true;
          }

        void transactProxy () throws IOException, ServletException
          {
            //////////////////////////////////////////////////////////
            // We have a proxy but no one is currently requesting it.
            // We simpy have to wait for a timeout or a real task.
            //////////////////////////////////////////////////////////
            synchronized (proxy_worker)
              {
                if (proxy_worker.perform (server_configuration.proxy_timeout))
                  {
                    // We got some real data!
                    proxy_response.getOutputStream ().write (InternalObjectStream.writeObject (request_descriptor.request_object));
                  }
                else
                  {
                    // We never got a hit and have to remove this proxy from the list...
                    int q = 0;
                    for (ProxyRequest proxy : proxies)
                      {
                        if (proxy.proxy_id == proxy_id)
                          {
                            proxies.remove (q);
                            break;
                          }
                        q++;
                      }
                  }
              }
          }

        void transactResponse () throws IOException, ServletException
          {
            request_descriptor.transactResponse ();
          }
      }

    private void returnInternalFailure (HttpServletResponse response, String message) throws IOException
      {
        logger.severe (message);
        if (error_container == null)
          {
            response.sendError (HttpServletResponse.SC_INTERNAL_SERVER_ERROR, message);
          }
        else
          {
            try
              {
                ProxyServerErrorFactory server_error = error_container.newInstance ();
                server_error.setMessage (message);
                response.setContentType (server_error.getMIMEtype ());
                response.getOutputStream ().write (server_error.getContent ());
              }
            catch (InstantiationException e)
              {
                throw new IOException (e);
              }
            catch (IllegalAccessException e)
              {
                throw new IOException (e);
              }
          }
      }

    /**
     * Proxy server status method.
     * <p>
     * 
     * @return The number of proxy channels that are in a waiting state.
     */
    public synchronized int getProxyQueueLength ()
      {
        return proxies.size ();
      }

    /**
     * Proxy server status method.
     * <p>
     * 
     * @return The number of request timeout errors occurred so far.
     */
    public int getRequestTimeouts ()
      {
        return request_timeout_errors;
      }

    /**
     * Proxy server status method.
     * <p>
     * 
     * @return The number of response timeout errors occurred so far.
     */
    public int getResponseTimeouts ()
      {
        return response_timeout_errors;
      }

    /**
     * Proxy server status method.
     * <p>
     * 
     * @return The last (if any) request object. Will be <code>null</code> if
     *         there has been no external access yet.
     */
    public synchronized ProxyRequestInterface getLastRequestObject ()
      {
        return last_request;
      }

    /**
     * Proxy server status method.
     * <p>
     * 
     * @return The instance ID of the proxy client. Will be <code>null</code> if
     *         the proxy client has not yet called the proxy server.
     */
    public synchronized String getProxyClientID ()
      {
        return server_configuration == null ? null : server_configuration.client_id;
      }

    private synchronized void cleanUpAfterFailedCall (RequestDescriptor request_descriptor, String err) throws IOException
      {
        long caller_id = request_descriptor.request_object.caller_id;
        int q = 0;
        for (RequestDescriptor rd : waiting_callers)
          {
            if (rd.request_object.caller_id == caller_id)
              {
                waiting_callers.remove (q);
                logger.info ("Request queue object removed after fail");
                break;
              }
            q++;
          }
        q = 0;
        for (RequestDescriptor rd : response_queue)
          {
            if (rd.request_object.caller_id == caller_id)
              {
                response_queue.remove (q);
                logger.info ("Response queue object removed after fail");
                break;
              }
            q++;
          }
        returnInternalFailure (request_descriptor.response, "Internal server error");
      }

    private synchronized Caller processRequest (HttpServletResponse response, ProxyRequestInterface request_object) throws IOException, ServletException
      {
        // Create a descriptor
        RequestDescriptor rd = new RequestDescriptor ();
        rd.response = response;
        rd.request_object = new InternalRequestObject (last_request = request_object, next_caller_id++);
        response_queue.add (rd);

        // Now check if there is a proxy that can take this request
        if (proxies.isEmpty ())
          {
            // No - put in waiting list
            waiting_callers.add (rd);
            return rd;
          }
        // Yes - take it!
        ProxyRequest preq = proxies.remove (0);
        preq.setCaller (rd);
        return preq;
      }

    /**
     * Proxy external call handler.
     * <p>
     * This method forwards an external call through the proxy tunnel, as well
     * as returning the associated response data.
     * 
     * @param response
     *          The response object of the external call Servlet.
     * @param proxy_request_object
     *          The request data object.
     */
    public void processCall (ProxyRequestInterface proxy_request_object, HttpServletResponse response) throws IOException, ServletException
      {
        ////////////////////////////////////////////////////////////////////////////////
        // Perform as much as possible of the "heavy" stuff outside of synchronization
        ////////////////////////////////////////////////////////////////////////////////

        if (server_configuration == null)
          {
            returnInternalFailure (response, "Proxy not started yet!");
            return;
          }

        ////////////////////////////////////////////////////////////////////
        // Insert request into queues etc.
        ////////////////////////////////////////////////////////////////////
        Caller ci = processRequest (response, proxy_request_object);

        ///////////////////////////////////////////////////
        // Now process the action of the request part
        ///////////////////////////////////////////////////
        if (ci.transactRequest ())
          {

            ////////////////////////////////////////////////////////
            // Success! Now process the action of the response part
            ////////////////////////////////////////////////////////
            ci.transactResponse ();
          }
      }

    private synchronized RequestDescriptor findProxyRequest (long caller_id)
      {
        int q = 0;
        for (RequestDescriptor rd : response_queue)
          {
            if (rd.request_object.caller_id == caller_id)
              {
                response_queue.remove (q);
                return rd;
              }
            q++;
          }
        return null;
      }

    private synchronized Caller addProxyWorker (HttpServletResponse response) throws IOException, ServletException
      {
        // Create a descriptor
        ProxyRequest preq = new ProxyRequest ();
        preq.proxy_response = response;
        preq.proxy_id = next_proxy_id++;

        // Now check if there is a caller in need for some help
        if (waiting_callers.isEmpty ())
          {
            // No - just go and wait
            proxies.add (preq);
            return preq;
          }
        // Yes - take it!
        RequestDescriptor pd = waiting_callers.remove (0);
        pd.setProxyWorker (preq);
        return pd;
      }

    private synchronized void resetProxy (InternalServerConfiguration server_conf)
      {
        next_caller_id = 0;
        next_proxy_id = 0;
        response_timeout_errors = 0;
        request_timeout_errors = 0;
        last_request = null;
        proxies.clear ();
        response_queue.clear ();
        waiting_callers.clear ();
        server_configuration = server_conf;
        logger.info ("Proxy " + (server_conf == null ? "RESET" : "INIT" + (instance_name == null ? "" : " Name=" + instance_name) + " proxy-cycle=" + server_conf.proxy_timeout/1000 + "s") + " client-id=" + server_conf.client_id);
      }

    /**
     * Proxy server reset. Clears all internal variables and states. Typically
     * called by context destruction/reload in Servlets.
     */
    public void resetProxy ()
      {
        resetProxy (null);
      }

    private boolean wrongClientID (InternalClientObject client_object, HttpServletResponse response) throws IOException
      {
        if (server_configuration == null)
          {
            returnInternalFailure (response, "Proxy server not ready");
            return true;
          }
        if (server_configuration.client_id.equals (client_object.client_id))
          {
            return false;
          }
        returnInternalFailure (response, "Proxy client ID error " + server_configuration.client_id + " versus " + client_object.client_id);
        return true;
      }

    /**
     * Proxy client call handler.
     * <p>
     * This method processes a call from the proxy client.
     * 
     * @param request
     *          The request object of the proxy server Servlet.
     * @param response
     *          The response object of the proxy server Servlet.
     */
    public void processProxyCall (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        ////////////////////////////////////////////////////////////////////////////////
        // Perform as much as possible of the "heavy" stuff outside of
        // synchronization
        ////////////////////////////////////////////////////////////////////////////////
        ServletInputStream is = request.getInputStream ();
        byte[] buf = new byte[4096];
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        int n;
        while ((n = is.read (buf)) != -1)
          {
            baos.write (buf, 0, n);
          }
        byte[] data = baos.toByteArray ();

        /////////////////////////////////////////////////
        // Ready to process an authenticated call
        /////////////////////////////////////////////////
        try
          {
            Object object = InternalObjectStream.readObject (data, this);
            if (object instanceof InternalServerConfiguration)
              {

                ////////////////////////////////////////////////
                // First call. Reset all, get configuration
                ////////////////////////////////////////////////
                resetProxy ((InternalServerConfiguration) object);
              }
            else if (object instanceof InternalResponseObject)
              {
                ////////////////////////////////////////////////
                // Data to process!
                ////////////////////////////////////////////////
                InternalResponseObject ro = (InternalResponseObject) object;
                if (wrongClientID (ro, response))
                  {
                    return;
                  }
                RequestDescriptor rd = findProxyRequest (ro.caller_id);
                if (rd != null)
                  {
                    rd.response_object = ro;
                    rd.response_waiter.haveData4You ();
                  }
              }
            else if (object instanceof InternalUploadObject)
              {
                ////////////////////////////////////////////////
                // Must be an "Upload" object
                ////////////////////////////////////////////////
                InternalUploadObject upload = (InternalUploadObject) object;
                if (wrongClientID (upload, response))
                  {
                    return;
                  }
                for (ProxyUploadHandler handler : upload_event_subscribers)
                  {
                    handler.handleUploadedData (upload.getPayload (handler));
                  }
              }
            else
              {
                ////////////////////////////////////////////////
                // Must be an "Idle" object
                ////////////////////////////////////////////////
                InternalIdleObject idle = (InternalIdleObject) object;
                if (wrongClientID (idle, response))
                  {
                    return;
                  }
              }
          }
        catch (ClassNotFoundException e)
          {
            logger.severe (e.getMessage ());
            returnInternalFailure (response, "Unrecognized object (check versions)");
            return;
          }
        Caller ci = addProxyWorker (response);
        ci.transactProxy ();
      }

  }
