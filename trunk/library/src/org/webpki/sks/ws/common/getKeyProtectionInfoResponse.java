
package org.webpki.sks.ws.common;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="ProtectionStatus" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="blah" type="{http://www.w3.org/2001/XMLSchema}byte"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.NONE)
@XmlRootElement(name = "getKeyProtectionInfoResponse")
@XmlType(propOrder={"protection_info","blah"})
public class getKeyProtectionInfoResponse {
  
  public getKeyProtectionInfoResponse ()
    {
      System.out.println ("KPIR");
    }

    @XmlElement(name="ProtectionStatus", required = true)
    public String protection_info;
    @XmlElement(name="blah", required = true)
    public byte blah;
}
