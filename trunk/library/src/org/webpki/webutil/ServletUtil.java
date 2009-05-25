package org.webpki.webutil;

import java.io.IOException;
import java.io.DataInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.File;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.servlet.ServletContext;
import javax.servlet.ServletInputStream;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class ServletUtil
  {

    private ServletUtil () {}

    private static String getServerURL (HttpServletRequest request, String context)
      {
        StringBuffer r = new StringBuffer(request.isSecure() ? "https://" : "http://");
        
        if(request.getHeader("host") == null)
          {
            r.append(request.getServerName());

            if(request.getServerPort() != (request.isSecure() ? 443 : 80))
              {
                r.append(request.getServerPort());
              }
          }
        else
          {
            r.append(request.getHeader("host"));
          }
        
        r.append(context);
        
        return r.toString();
      }


    public static String getServerRootURL (HttpServletRequest request)
      {
        return getServerURL(request, "/");
      }


    public static String getContextURL (HttpServletRequest request)
      {
        return getServerURL(request, request.getContextPath ());
      }


    public static byte[] getData (HttpServletRequest request) throws java.io.IOException
      {
        int n = request.getContentLength ();
        ServletInputStream is = request.getInputStream ();
        if(n >= 0)
          {
            byte[] data = new byte[n];
            new DataInputStream (is).readFully (data);
            return data;
          }
        else
          {
            byte[] t = new byte[10240];
            ByteArrayOutputStream baos = new ByteArrayOutputStream ();
            while ((n = is.read (t)) != -1) 
              {
                baos.write (t, 0, n);         
              }
            return baos.toByteArray ();
          }
      }
    

    public static String getCookie (HttpServletRequest request, String name)
      {
        Cookie[] c = request.getCookies ();
        if (c != null)
          {
            for(int i = 0; i < c.length; i++)
              {
                if (c[i].getName ().equals (name))
                  {
                    return c[i].getValue ();
                  }
              }
          }
        
        return null;
      }

    
    public static KeyStore getKeyStore (ServletContext context, String certsfile, String password)
    throws IOException, GeneralSecurityException
      {
        FileInputStream file = new FileInputStream (context.getRealPath (File.separator + 
                                                                         "WEB-INF" +
                                                                         File.separator + 
                                                                         "classes" +
                                                                         File.separator +
                                                                         certsfile));
        KeyStore ks = KeyStore.getInstance ("JKS");
        ks.load (file, password.toCharArray ());
        return ks;
      }


  }
