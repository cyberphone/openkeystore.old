/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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
package org.webpki.sks.ws.server;

///////////////////////////////////////////////
// Generated by WSCreator 1.0 - Do not edit! //
///////////////////////////////////////////////

import java.util.ArrayList;
import java.util.List;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import javax.xml.ws.Endpoint;
import javax.xml.ws.Holder;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;

import org.webpki.sks.SKSException;

/**
 *  This is the server :-)
 */
@com.sun.xml.ws.developer.SchemaValidation
@WebService(serviceName="SKSWS",
            targetNamespace="http://xmlns.webpki.org/sks/v0.61",
            name="SKSWS.Interface",
            portName="SKSWS.Port",
            wsdlLocation="META-INF/SKSWS.wsdl")
public class SKSWSImplementation
  {
    @WebMethod(operationName="abortProvisioningSession")
    @RequestWrapper(localName="abortProvisioningSession", targetNamespace="http://xmlns.webpki.org/sks/v0.61")
    @ResponseWrapper(localName="abortProvisioningSession.Response", targetNamespace="http://xmlns.webpki.org/sks/v0.61")
    public void abortProvisioningSession (@WebParam(name="keyHandle")
                                          int keyHandle)
    throws SKSException
      {
        if (keyHandle == 5)
          {
            throw new SKSException ("bad",4);
          }
      }

    @WebMethod(operationName="getKeyProtectionInfo")
    @RequestWrapper(localName="getKeyProtectionInfo", targetNamespace="http://xmlns.webpki.org/sks/v0.61")
    @ResponseWrapper(localName="getKeyProtectionInfo.Response", targetNamespace="http://xmlns.webpki.org/sks/v0.61")
    public void getKeyProtectionInfo (@WebParam(name="keyHandle")
                                      int keyHandle,
                                      @WebParam(name="ProtectionStatus", mode=WebParam.Mode.OUT)
                                      Holder<String> protectionStatus,
                                      @WebParam(name="blah", mode=WebParam.Mode.OUT)
                                      Holder<Byte> blah,
                                      @WebParam(name="X509Certificate", mode=WebParam.Mode.OUT)
                                      Holder<List<byte[]>> x509_certificate)
    throws SKSException
      {
        protectionStatus.value = "yes";
        blah.value = (byte)(keyHandle + 2);
        List<byte[]> certs = new ArrayList<byte[]> ();
        certs.add (new byte[]{3,4,5});
        certs.add (new byte[]{3,4,8,9});
        x509_certificate.value = certs;
      }

    @WebMethod(operationName="setCertificatePath")
    @RequestWrapper(localName="setCertificatePath", targetNamespace="http://xmlns.webpki.org/sks/v0.61")
    @ResponseWrapper(localName="setCertificatePath.Response", targetNamespace="http://xmlns.webpki.org/sks/v0.61")
    public void setCertificatePath (@WebParam(name="KeyHandle")
                                    int key_handle,
                                    @WebParam(name="X509Certificate")
                                    List<byte[]> x509_certificate,
                                    @WebParam(name="MAC")
                                    byte[] mac)
    throws SKSException
      {
        System.out.println ("Certs=" + (x509_certificate.size() == 0 ? "'null'" : x509_certificate.size ()) + " mac=" + mac.length);
      }

    @WebMethod(operationName="getVersion")
    @RequestWrapper(localName="getVersion", targetNamespace="http://xmlns.webpki.org/sks/v0.61")
    @ResponseWrapper(localName="getVersion.Response", targetNamespace="http://xmlns.webpki.org/sks/v0.61")
    @WebResult(name="return")
    public String getVersion ()
      {
        return "0.00001";
      }

    public static void main (String[] args)
      {
        if (args.length != 1)
          {
            System.out.println ("Missing URL");
          }
        Endpoint endpoint = Endpoint.create (new SKSWSImplementation ());
        endpoint.publish (args[0]);
      }
  }
