package phone;

import java.io.IOException;

import java.net.URL;

import java.util.Vector;
import java.util.HashMap;

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.net.HttpsWrapper;
import org.webpki.net.XBPP;

import org.webpki.util.HTMLParser;
import org.webpki.util.HTMLParserURLRewriter;
import org.webpki.webutil.ServletUtil;

import org.webpki.xml.XMLSchemaCache;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.wasp.SignatureRequestDecoder;
import org.webpki.wasp.AuthenticationRequestDecoder;

import org.webpki.keygen2.KeyOperationRequestDecoder;
import org.webpki.keygen2.CredentialDeploymentRequestDecoder;
import org.webpki.keygen2.PlatformNegotiationRequestDecoder;

import misc.ProtectedServlet;


public class PhoneUtil
  {

    static XMLSchemaCache schema_cache;

    static HashMap<String,String> ns2url;

    static void initCache (Class<?> cl, String url) throws Exception
      {
        schema_cache.addWrapper (cl);
        ns2url.put (cl.getCanonicalName (), url);
      }

    static
      {
        try
          {
            ns2url = new HashMap<String,String> ();
            schema_cache = new XMLSchemaCache ();
            initCache (SignatureRequestDecoder.class, "phonewinsignreq");
            initCache (AuthenticationRequestDecoder.class, "phonewinauthreq");
            initCache (PlatformNegotiationRequestDecoder.class, "phonewinkg2init");
            initCache (KeyOperationRequestDecoder.class, null);
            initCache (CredentialDeploymentRequestDecoder.class, null);
          }
        catch (Exception e)
          {
          }
      }

    private static final String COOKIEJAR               = "COOKIEJAR";

    private static final String PROTOCOL_OBJECT         = "PROTOCOL_OBJECT";

    private static final String HTTPS_CERT              = "HTTPS_CERT";    private static final String DEFERRED_CERTIFICATION  = "DEFERRED_CERTIFICATION";

    private static void setUserAgent (HttpsWrapper wrap) throws IOException
      {
        wrap.setHeader ("User-Agent", "WebPKI.org Phone Emulator");
      }


    private static class CookieJar
      {
        HashMap<String,HashMap<String,String>> cookies = new HashMap<String,HashMap<String,String>> ();
      }

    public static XMLObjectWrapper getXMLObject (HttpSession session) throws IOException
      {
        return (XMLObjectWrapper) session.getAttribute (PROTOCOL_OBJECT);
      }


    private static CookieJar getCookieJar (HttpServletRequest request) throws IOException
      {
        HttpSession session = request.getSession (false);
        if (session == null)
          {
            ProtectedServlet.bad ("Session not found");
          }
        CookieJar cookie_jar = (CookieJar) session.getAttribute (COOKIEJAR);
        if (cookie_jar == null)
          {
            session.setAttribute (COOKIEJAR, cookie_jar = new CookieJar ());
          }
        return cookie_jar;
      }


    private static void setCookieToCache (HttpServletRequest request, String url, String raw_cookie) throws IOException
      {
        String path;
        int index;

        CookieJar cookie_jar = getCookieJar (request);

        /* Construct path. */
        if ((index = raw_cookie.indexOf ("Path=")) != -1)
          {
            path = raw_cookie.substring (index + 5);
            if ((index = path.indexOf (';')) > 0)
              {
                path = path.substring (0, index).trim ();
              }
          }
        else
          {
            path = "";
          }
        index = raw_cookie.indexOf (';');
        String clean_cookie = raw_cookie.substring (0, index).trim ();
           
        URL full = new URL (url);
        String sub = new URL (full, path).toString ();
        
        /* Check if cookie URL exist */
        HashMap<String,String> cookies = cookie_jar.cookies.get (sub);
        if (cookies == null)
          {
            cookie_jar.cookies.put (sub, cookies = new HashMap<String,String> ());
          }
        index = clean_cookie.indexOf ('=');
        cookies.put (clean_cookie.substring (0, index++), index == clean_cookie.length () ? null : clean_cookie.substring (index));
      }

    private static void readEmittedCookies (HttpServletRequest request, HttpsWrapper wrap, String url) throws IOException
      {
        String set_cookie;
        if ((set_cookie = wrap.getHeaderValue ("Set-Cookie")) != null)
          {
            setCookieToCache (request, url, set_cookie);
          }
      }


    private static HttpsWrapper getHttpsWrapper ()
      {
        HttpsWrapper wrap = new HttpsWrapper ();
        wrap.setTimeout (40000);
        wrap.setFollowRedirects (false);
        wrap.setRequireSuccess (true);
        return wrap;
      }

    
    private static String check4Redirect (IOException hwe, HttpServletRequest request, HttpsWrapper wrap, String url) throws IOException
      {
        if (wrap.getResponseCode() != 302) throw hwe;
        String redir_url = wrap.getHeaderValue ("Location");
        if (redir_url != null)
          {
            URL new_url = new URL (new URL (url), redir_url);
            url = new_url.toString ();
            readEmittedCookies (request, wrap, url);
          }
        else
          {
            throw new IOException ("Redirected without any URL");
          }
        return url;
      }


    private static class HTMLReplacer implements HTMLParserURLRewriter
      {
        URL context_url;
        HttpServletRequest request;

        HTMLReplacer (HttpServletRequest request, String context_url) throws IOException
          {
            this.request = request;
            this.context_url = new URL (context_url);
          }

        public String rewriteURL (String url) throws IOException
          {
            return PhoneWinProxy.createProxyURL (request, new URL (context_url, url).toString ());
          }
      }
    static void setDeferredCertificationHandler (HttpSession session, String page)      {
        session.setAttribute (DEFERRED_CERTIFICATION, page);      }

    private static boolean handleResponse (HttpServletRequest request, 
                                           HttpServletResponse response,
                                           HttpsWrapper wrap,
                                           String url) throws IOException
      {
        String content_type = wrap.getContentType ();
        if (content_type.startsWith ("text/html"))
          {
            /* HTML - adjust URLs of internal objects to the proxy mode */

            if (response == null)
              {
                return false;  // This is an ugly hack for a specific "rigged" setup (QuickRun)
              }
            response.setContentType (content_type);
            response.setDateHeader ("Expires", 0);
            response.getOutputStream ().print (HTMLParser.parse (wrap.getDataUTF8 (), new HTMLReplacer (request, url)));
            return true;
          }
        else if (content_type.startsWith (XBPP.XBPP_MIME_TYPE))
          {
            /* Our favorite... */

            HttpSession session = request.getSession (false);
            if (session == null)
              {
                ProtectedServlet.bad ("Session not found");
              }
            session.setAttribute (HTTPS_CERT, wrap.getServerCertificate ());
            XMLObjectWrapper o = schema_cache.parse (wrap.getData ());
            session.setAttribute (PROTOCOL_OBJECT, o);
            PhoneDebugWin.setDebugReceivedXML (session, o.element (), wrap.getData ());
            String action_url = ns2url.get (o.getClass ().getCanonicalName ());            if (action_url == null)
              {
                if (session.getAttribute (DEFERRED_CERTIFICATION) == null)                  {
                    return false;                  }                action_url = (String)session.getAttribute (DEFERRED_CERTIFICATION);                setDeferredCertificationHandler (session, null);
              }
            response.sendRedirect (ServletUtil.getContextURL (request) + "/" + action_url);
            return true;
          }
        else
          {
            /* Let other data simply pass through */
            response.setContentType (content_type);
            String hs;
            if ((hs = wrap.getHeaderValue ("ETag")) != null)
              {
                response.setHeader ("ETag", hs);
              }
            if ((hs = wrap.getHeaderValue ("Last-Modified")) != null)
              {
                response.setHeader ("Last-Modified", hs);
              }
            response.setContentLength (wrap.getData ().length);
            response.getOutputStream ().write (wrap.getData ());
            return true;
          }
      }

    /*
     * Wraps the HttpsWrapper POST requests.
     */
    static boolean makePostRequest (HttpServletRequest request, HttpServletResponse response, String url, byte[] post_data, String content_type) throws IOException
      {
        HttpsWrapper wrap = getHttpsWrapper ();
        boolean success = false;
        int count = 0;

        while (!success && count++ < 5)
          {
            try
              {
                setUserAgent (wrap);
                setCookies (request, wrap, url);
                if (count <= 1)
                  {
                    /* Handle as any POST */
                    wrap.setHeader ("Content-Type", content_type);
                    wrap.makePostRequest (url, post_data);
                    success = true;
                  }
                else
                  {
                    /* Redirects are GETs */
                    wrap.makeGetRequest (url);
                    success = true;
                  }
                readEmittedCookies (request, wrap, url);
              }
            catch (IOException hwe)
              {
                url = check4Redirect (hwe, request, wrap, url);
              }
          }

        if (!success && count == 5)
          {
            throw new IOException( "Redirected too many times");
          }
        return handleResponse (request, response, wrap, url);
      }


    /*
     * Wraps the HttpsWrapper GET requests.
     */
    static boolean makeGetRequest (HttpServletRequest request, HttpServletResponse response, String url) throws IOException
      {
        HttpsWrapper wrap = getHttpsWrapper ();
        boolean success = false;
        int count = 0;

        while (!success && count++ < 5)
          {
            try
              {
                setUserAgent (wrap);
                setCookies (request, wrap, url);
                wrap.makeGetRequest (url);
                success = true;
                readEmittedCookies (request, wrap, url);
              }
            catch (IOException hwe)
              {
                url = check4Redirect (hwe, request, wrap, url);
              }
          }

        if (!success && count == 5)
          {
            throw new IOException ("Redirected too many times");
          }

        return handleResponse (request, response, wrap, url);
      }


    static boolean writeXMLObject (HttpSession session,
                                   HttpServletRequest request,
                                   HttpServletResponse response,
                                   XMLObjectWrapper o,
                                   String url) throws IOException
      {
        byte[] data = o.writeXML ();
        PhoneDebugWin.setDebugSentXML (session, o.element (), data);
        return makePostRequest (request, response, url, data, XBPP.XBPP_MIME_TYPE);
      }

    static X509Certificate getServerCertificate (HttpSession session) throws IOException
      {
        return (X509Certificate) session.getAttribute (HTTPS_CERT);
      }

    private static String[] getCookies (HttpServletRequest request, String url) throws IOException
      {
        Vector<String> v = new Vector<String>();
        CookieJar cookie_jar = getCookieJar (request);
        for (String cookie_url : cookie_jar.cookies.keySet ())
          {
            if (url.startsWith (cookie_url))
              {
                for (String cookie : cookie_jar.cookies.get (cookie_url).keySet ())
                  {
                    v.add (cookie + "=" + cookie_jar.cookies.get (cookie_url).get (cookie));
                  }
              }
          }
        return v.isEmpty () ? null : v.toArray (new String[0]);
      }


   private static void setCookies (HttpServletRequest request, HttpsWrapper wrap, String url) throws IOException
     {
        String[] cookies;

        if ((cookies = getCookies (request, url)) != null)
          {
            for (int i = 0; i < cookies.length; i++)
              {
                wrap.setHeader ("Cookie", cookies[i]);
              }
          }
      }

  }

