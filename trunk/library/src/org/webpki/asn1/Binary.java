package org.webpki.asn1;

import java.io.IOException;
import org.webpki.util.ArrayUtil;

public abstract class Binary extends Simple
  {
    byte[] value;
    
    public byte[] value()
      {
        byte[] r = new byte[value.length];
        System.arraycopy(value, 0, r, 0, value.length);
        return r;
      }
    
    public byte value(int i)
      {
        return value[i];
      }
    
    public int length()
      {
        return value.length;
      }
      
    public BaseASN1Object derDecodeValue() throws IOException
      {
        return DerDecoder.decode(value);
      }
    
    public Object objValue()
      {
        return value();
      }
    
    Binary(int tagClass, int tagNumber, boolean primitive, byte[] value)
      {
        super(tagClass, tagNumber, primitive);
        if(value == null)
          {
            throw new IllegalArgumentException("Binary must have a (non-null) value.");
          }
        this.value = new byte[value.length];
        System.arraycopy(value, 0, this.value, 0, value.length);
      }

    Binary(int tagNumber, boolean primitive, byte[] value)
      {
        this(UNIVERSAL, tagNumber, primitive, value);
      }

    Binary(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }

    public boolean diff(BaseASN1Object o, StringBuffer s, String prefix)
      {
        if(!sameType(o) || !ArrayUtil.compare(value, ((Binary)o).value))
          {
            s.append(prefix).append("<-------    ");//.append('\n');
            toString(s, prefix);
            s.append('\n');
            s.append(prefix).append("------->    ");//.append('\n');
            o.toString(s, prefix);
            s.append('\n');
            return true;
          }
        
        if(isPrimitive() != o.isPrimitive())
          {
            s.append(prefix).append("<------- " + (isPrimitive() ? "primitive" : "contructed")).append("    ");
            toString(s, prefix);
            s.append('\n');
            s.append(prefix).append("------->" + (o.isPrimitive() ? "primitive" : "contructed")).append("    ");
            o.toString(s, prefix);
            s.append('\n');
            return true;
          }
        
        if(blob != null && o.blob != null &&
           encodedLength != o.encodedLength)
          {
            s.append(prefix).append("<------- length " + encodedLength).append("    ");
            toString(s, prefix);
            s.append('\n');
            s.append(prefix).append("-------> length " + o.encodedLength).append("    ");
            o.toString(s, prefix);
            s.append('\n');
            return true;
          }
        
        return false;
      }

    void extractableStringData (StringBuffer s, String prefix)
      {
        if (decoder.extractfromoctetstrings && (value[0] == 0x30 ||
            (this instanceof ASN1OctetString && (value[0] == 0x03 || value[0] == 0x04))))
          {
            try
              {
                StringBuffer enc = new StringBuffer ();
                DerDecoder dd = new DerDecoder(value);
                dd.extractfromoctetstrings = decoder.extractfromoctetstrings;
                dd.bytenumbers = decoder.bytenumbers;
                dd.bytenumlistoffset = blobOffset + encodedLength - value.length;
                dd.readNext().toString(enc, prefix + "    ");
                s.append ("encapsulates\n  " + getByteNumberBlanks ()+ prefix + "{\n");
                s.append (enc);
                s.append ("\n  " + getByteNumberBlanks ()+ prefix + "}");
               return;
              }
            catch (Exception e)
              {
              }
          }
        s.append(value.length).append(" bytes");
        hexData (s, value);
      }
  }
