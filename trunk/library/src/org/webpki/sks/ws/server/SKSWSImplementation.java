package org.webpki.sks.ws.server;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.xml.namespace.QName;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.Endpoint;
import javax.xml.ws.Holder;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;

import org.webpki.sks.SKSException;

@com.sun.xml.ws.developer.SchemaValidation
@WebService(targetNamespace="http://xmlns.webpki.org/sks/v0.61",
            serviceName="SKSWS",
            name="SKSWS.Interface",
            portName="SKSWS.Port",
            wsdlLocation="META-INF/SKSWS.wsdl")
/*
 * Usage in JBoss: 
 * Remove @SchemaValidation. 
 * Put code in a WAR.
 * Set wsdlLocation="/WEB-INF/wsdl/SKSWS.wsdl"
 */
public class SKSWSImplementation
  {

    @WebMethod
    public void abortProvisioningSession(
        @WebParam(name = "keyHandle", targetNamespace = "")
        int keyHandle)
        throws SKSException
    {
      if (keyHandle == 5)
        {
          throw new SKSException ("bad",4);
        }
      // TODO Auto-generated method stub
      
    }


    @WebMethod(operationName="getKeyProtectionInfo")
    @RequestWrapper(localName = "getKeyProtectionInfo", targetNamespace = "http://xmlns.webpki.org/sks/v0.61")
    @ResponseWrapper(localName = "getKeyProtectionInfo.Response", targetNamespace = "http://xmlns.webpki.org/sks/v0.61")
     public void getKeyProtectionInfo(
        @WebParam(name = "keyHandle", targetNamespace = "")
        int keyHandle,
        @WebParam(name = "ProtectionStatus", targetNamespace = "", mode = WebParam.Mode.OUT)
        Holder<String> protectionStatus,
        @WebParam(name = "blah", targetNamespace = "", mode = WebParam.Mode.OUT)
        Holder<Byte> blah,
        @WebParam(name = "X509Certificate", targetNamespace = "", mode = WebParam.Mode.OUT)
        Holder<List<byte[]>> x509_certificate)
      throws SKSException
    {
      protectionStatus.value = "yes";
      blah.value = (byte)(keyHandle + 2);
      List certs = new ArrayList ();
      certs.add (new byte[]{3,4,5});
      certs.add (new byte[]{3,4,8,9});
      x509_certificate.value = certs;
    }

    @WebMethod
    public void setCertificatePath(
        @WebParam(name = "KeyHandle", targetNamespace = "")
        int key_handle,
        @WebParam(name = "X509Certificate", targetNamespace = "")
        List<byte[]> x509_certificate,
        @WebParam(name = "MAC", targetNamespace = "")
        byte[] mac)
        throws SKSException
        {
          System.out.println ("Certs=" + x509_certificate.size () + " mac=" + mac.length);
        }

  @WebMethod
  @WebResult(name="return", targetNamespace = "")
  public String getVersion()
    {
      // TODO Auto-generated method stub
      return "0.00001";
    }

    public static void main (String[] args)
      {
        if (args.length != 1)
          {
            System.out.println ("Missing URL");
          }
/*
        URL wsdlResource = SKSWSImplementation.class.getResource ("/META-INF/SKSWS.wsdl");

        List<Source> metadata = new ArrayList<Source> ();

        Source source = new StreamSource (wsdlResource.openStream ());
        source.setSystemId (wsdlResource.toExternalForm ());
        metadata.add (source);

        Map<String,Object> properties = new HashMap<String,Object> ();

        properties.put (Endpoint.WSDL_PORT, new QName ("http://xmlns.webpki.org/sks/v0.61", "SKSWS.Port"));
        properties.put (Endpoint.WSDL_SERVICE, new QName ("http://xmlns.webpki.org/sks/v0.61", "SKSWS"));
*/
        
        Endpoint endpoint = Endpoint.create (new SKSWSImplementation ());
//        endpoint.setMetadata (metadata);
//        endpoint.setProperties (properties);
        endpoint.publish (args[0]);
      }

  }
