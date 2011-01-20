package org.webpki.sks.ws.client;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.ws.Holder;

import javax.xml.ws.BindingProvider;

public class SKSWSClient
  {
    private SKSWSProxy proxy;
    
    private String port;
    
    
    public SKSWSClient (String port)
      {
        this.port = port;
      }

    /**
     * Factory method. Each WS call should use this method.
     * 
     * @return A handle to a fresh WS instance
     */
    public SKSWSProxy getSKSWS ()
    {
        if (proxy == null)
        {
            synchronized (this)
            {
                SKSWS service = new SKSWS ();
                SKSWSProxy temp_proxy = service.getSKSWSPort ();
                Map<String,Object> request_object = ((BindingProvider) temp_proxy).getRequestContext ();
                request_object.put (BindingProvider.ENDPOINT_ADDRESS_PROPERTY, port);
                proxy = temp_proxy;
            }
        }
        return proxy;
    }

    static void bad ()
    {
     throw new RuntimeException ("baddy"); 
    }
    
    /**
     * Test method. Use empty argument list for help.
     * 
     * @param args
     *            Command line arguments
     * @throws  
     * @throws SKSExceptionBean 
     */
    public static void main (String args[])
    {
        if (args.length != 1)
        {
            System.out.println ("SKSWSClient port");
            System.exit (3);
        }
        SKSWSClient client = new SKSWSClient (args[0]);
        SKSWSProxy proxy = client.getSKSWS ();
        System.out.println ("Version=" + proxy.getVersion ());
        
        try
          {
            proxy.abortProvisioningSession (5);
            bad ();
          }
        catch (SKSException_Exception e)
          {
            System.out.println ("Ok e=" + e.getFaultInfo ().getError () + " m=" + e.getFaultInfo ().getMessage ());
          }

        Holder<Byte> blah = new Holder<Byte> ();
        Holder<String> prot = new Holder<String> ();
        try
          {
            proxy.getKeyProtectionInf (4, prot, blah);
            if (!prot.value.equals ("yes"))
              {
                bad ();
              }
            if (blah.value != 6)
              {
                bad ();
              }
            System.out.println ("Ok=getkey");

            List<byte[]> certs = new ArrayList<byte[]> ();
            certs.add (new byte[]{4,6});
            certs.add (new byte[]{4,6,7});
            
            proxy.setCertificatePath (8,certs, new byte[]{4,6});
            new SKSWSClient (args[0]).getSKSWS ();
          }
        catch (SKSException_Exception e)
          {
            bad ();
          }
    }    

  }
