/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.json;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigDecimal;
import java.math.BigInteger;

import java.security.cert.X509Certificate;

import java.util.GregorianCalendar;
import java.util.Vector;

import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

/**
 * Reads JSON array elements.<p>
 * Data types are dealt with as in {@link JSONObjectReader}.</p>
 * @see JSONObjectReader#getArray(String)
 * @see JSONObjectReader#getJSONArrayReader()
 * @see #getArray()
 */
public class JSONArrayReader implements Serializable {

    private static final long serialVersionUID = 1L;

    Vector<JSONValue> array;

    int index;

    JSONArrayReader(Vector<JSONValue> array) {
        this.array = array;
    }

    public boolean hasMore() {
        return index < array.size();
    }

    void inRangeCheck() throws IOException {
        if (!hasMore()) {
            throw new IOException("Trying to read past of array limit: " + index);
        }
    }

    Object get(JSONTypes expectedType) throws IOException {
        inRangeCheck();
        JSONValue value = array.elementAt(index++);
        value.readFlag = true;
        JSONTypes.compatibilityTest(expectedType, value);
        return value.value;
    }

    public String getString() throws IOException {
        return (String) get(JSONTypes.STRING);
    }

    public int getInt() throws IOException {
        return JSONObjectReader.parseInt((String) get(JSONTypes.NUMBER));
    }

    public long getInt53() throws IOException {
        return JSONObjectReader.parseLong((String) get(JSONTypes.NUMBER));
    }

    public long getLong() throws IOException {
        return JSONObjectReader.convertBigIntegerToLong(getBigInteger());
    }

    public double getDouble() throws IOException {
        return Double.valueOf((String) get(JSONTypes.NUMBER));
    }

    public BigInteger getBigInteger() throws IOException {
        return JSONObjectReader.parseBigInteger(getString());
    }

    public BigDecimal getBigDecimal() throws IOException {
        return JSONObjectReader.parseBigDecimal(getString(), null);
    }

    public BigDecimal getBigDecimal(Integer decimals) throws IOException {
        return JSONObjectReader.parseBigDecimal(getString(), decimals);
    }

    public GregorianCalendar getDateTime() throws IOException {
        return ISODateTime.parseDateTime(getString());
    }

    public byte[] getBinary() throws IOException {
        return Base64URL.decode(getString());
    }

    public boolean getBoolean() throws IOException {
        return new Boolean((String) get(JSONTypes.BOOLEAN));
    }

    public boolean getIfNULL() throws IOException {
        if (getElementType() == JSONTypes.NULL) {
            scanAway();
            return true;
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    public JSONArrayReader getArray() throws IOException {
        return new JSONArrayReader((Vector<JSONValue>) get(JSONTypes.ARRAY));
    }

    public JSONTypes getElementType() throws IOException {
        inRangeCheck();
        return array.elementAt(index).type;
    }

    public JSONObjectReader getObject() throws IOException {
        return new JSONObjectReader((JSONObject) get(JSONTypes.OBJECT));
    }

    public void scanAway() throws IOException {
        get(getElementType());
    }

    public Vector<byte[]> getBinaryArray() throws IOException {
        Vector<byte[]> blobs = new Vector<byte[]>();
        do {
            blobs.add(getBinary());
        } while (hasMore());
        return blobs;
    }

    public X509Certificate[] getCertificatePath () throws IOException {
        return JSONSignatureDecoder.makeCertificatePath(getBinaryArray());
    }
}
