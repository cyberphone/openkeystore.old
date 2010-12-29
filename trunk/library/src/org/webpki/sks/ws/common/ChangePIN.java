
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
 *         &lt;element name="KeyHandle" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="Authorization" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *         &lt;element name="NewPIN" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "keyHandle",
    "authorization",
    "newPIN"
})
@XmlRootElement(name = "changePIN")
public class ChangePIN {

    @XmlElement(name = "KeyHandle")
    protected int keyHandle;
    @XmlElement(name = "Authorization", required = true)
    protected byte[] authorization;
    @XmlElement(name = "NewPIN", required = true)
    protected byte[] newPIN;

    /**
     * Gets the value of the keyHandle property.
     * 
     */
    public int getKeyHandle() {
        return keyHandle;
    }

    /**
     * Sets the value of the keyHandle property.
     * 
     */
    public void setKeyHandle(int value) {
        this.keyHandle = value;
    }

    /**
     * Gets the value of the authorization property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getAuthorization() {
        return authorization;
    }

    /**
     * Sets the value of the authorization property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setAuthorization(byte[] value) {
        this.authorization = ((byte[]) value);
    }

    /**
     * Gets the value of the newPIN property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getNewPIN() {
        return newPIN;
    }

    /**
     * Sets the value of the newPIN property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setNewPIN(byte[] value) {
        this.newPIN = ((byte[]) value);
    }

}
