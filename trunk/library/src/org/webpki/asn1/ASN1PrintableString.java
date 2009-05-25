package org.webpki.asn1;

import java.io.IOException;
import java.util.BitSet;
import org.webpki.util.StringUtil;

public class ASN1PrintableString extends ASN1String
  {
    public ASN1PrintableString(String value)
      {
        super(PRINTABLESTRING, value);
        StringUtil.checkAllowedChars(value, allowedChars);
      }

    ASN1PrintableString(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }

    private static BitSet allowedChars;
    
    static{
      allowedChars = StringUtil.charSet(" '+,-./:=?()");
      for(char c = 'a'; c <= 'z'; c++)
        {
          allowedChars.set(c);
        }
      for(char c = 'A'; c <= 'Z'; c++)
        {
          allowedChars.set(c);
        }
      for(char c = '0'; c <= '9'; c++)
        {
          allowedChars.set(c);
        }
    }
    
    /**
     * Checks if a string contains only characters allowable in a PrintableString.
     * <p>The folliwing characters are allowed (taken from section 3.3.3 of RFC1148)
     * <pre>  printablestring  = *( ps-char )
     *   ps-restricted-char = 1DIGIT /  1ALPHA / " " / "'" / "+"
     *                    / "," / "-" / "." / "/" / ":" / "=" / "?"
     *   ps-delim         = "(" / ")"
     *   ps-char          = ps-delim / ps-restricted-char</pre>
     * @return true iff <code><i>s</i></code> contains only characters allowable in a PrintableString.
     */
    public static boolean isPrintableString(String s)
      {
        return StringUtil.hasOnlyLegalChars(s, allowedChars);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("PrintableString '").append(value()).append('\'');
      }
  }
