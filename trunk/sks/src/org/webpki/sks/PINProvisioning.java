package org.webpki.sks;

import java.io.IOException;

import java.util.Vector;

import org.webpki.keygen2.KeyOperationRequestDecoder;
import org.webpki.keygen2.PassphraseFormats;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PatternRestrictions;


public class PINProvisioning
  {
    class PINEntry
      {
        KeyOperationRequestDecoder.PINPolicy pin_policy;

        boolean preset;

        String value;
      }

    Vector<PINEntry> pin_entries = new Vector<PINEntry> ();

    int index;

    public PINProvisioning (KeyOperationRequestDecoder decoder) throws IOException
      {
        for (KeyOperationRequestDecoder.RequestObjects ro : decoder.getRequestObjects ())
          {
            if (ro instanceof KeyOperationRequestDecoder.CreateKey)
              {
                KeyOperationRequestDecoder.CreateKey rk = (KeyOperationRequestDecoder.CreateKey) ro;
                if (rk.isStartOfPINPolicy ())
                  {
                    PINEntry pe = new PINEntry ();
                    pe.preset = rk.getPresetPIN () != null;
                    pe.pin_policy = rk.getPINPolicy ();
                    pin_entries.add (pe);
                  }
                else if (rk.getPINPolicy () != null &&
                         (rk.getPINPolicy ().getGrouping () == null ||
                          rk.getPINPolicy ().getGrouping () != PINGrouping.SHARED))
                  {
                    throw new IOException ("Only \"shared\" PIN groups implemented!");
                  }
              }
          }
      }

    public int size ()
      {
        return pin_entries.size ();
      }

    public int getMinLength () throws IOException
      {
        return pin_entries.elementAt (index).pin_policy.getMinLength ();
      }

    public int getMaxLength () throws IOException
      {
        return pin_entries.elementAt (index).pin_policy.getMaxLength ();
      }

    public boolean next () throws IOException
      {
        while (index < pin_entries.size ())
          {
            if (pin_entries.elementAt (index).preset)
              {
                index++;
              }
            else
              {
                return true;
              }
          }
        return false;
      }

    public boolean verify () throws IOException
      {
        return pin_entries.elementAt (index).value != null;
      }

    public PassphraseFormats getFormat () throws IOException
      {
        return pin_entries.elementAt (index).pin_policy.getFormat ();
      }

    public String setVerify (String value) throws IOException
      {
        if (pin_entries.elementAt (index).value.equals (value))
          {
            index++;
            return null;
          }
        pin_entries.elementAt (index).value = null;
        return "The PINs did not match.<br>Please start over again!";
      }

    public String setValue (String value) throws IOException
      {
        String error = pinCheck (value,
                                 getFormat (),
                                 getMinLength (),
                                 getMaxLength (),
                                 pin_entries.elementAt (index).pin_policy.getPatternRestrictions ());
        if (error == null)
          {
            pin_entries.elementAt (index).value = value;
          }
        return error;
      }

    static String pinCheck (String pin,
                            PassphraseFormats format,
                            int min_length,
                            int max_length,
                            PatternRestrictions[] pattern_restrictions)
      {
        if (pin.length () > max_length || pin.length () < min_length)
          {
            return "Bad PIN length";
          }
        if (format == PassphraseFormats.NUMERIC)
          {
            for (int i = 0; i < pin.length (); i++)
              {
                if (pin.charAt (i) < '0' || pin.charAt (i) > '9')
                  {
                    return "PIN must be numeric";
                  }
              }
          }
        if (pattern_restrictions != null)
          {
            for (PatternRestrictions pr : pattern_restrictions)
              {
                switch (pr)
                  {
                    case SEQUENCE:
                      char c = pin.charAt (0);
                      int f = pin.charAt (1) - c;
                      boolean seq = true;
                      for (int i = 1; i < pin.length (); i++)
                        {
                          if (f > 1 || f < -1 || c + f != pin.charAt (i))
                            {
                              seq = false;
                              break;
                            }
                          c = pin.charAt (i);
                        }
                      if (seq)
                        {
                          return "PIN must not be a sequence like 1234";
                        }
                      break;

                    case THREE_IN_A_ROW:
                      c = pin.charAt (0);
                      int same_count = 1;
                      for (int i = 1; i < pin.length (); i++)
                        {
                          if (c == pin.charAt (i))
                            {
                              if (++same_count == 3)
                                {
                                  return "PIN contains three of<br>the same digit in-a-row";
                                }
                            }
                          else
                            {
                              same_count = 1;
                            }
                          c = pin.charAt (i);
                        }
                      break;
                  }
              }
          }
        return null;
      }

    String getValue (KeyOperationRequestDecoder.PINPolicy pin_policy) throws IOException
      {
        for (PINEntry pe : pin_entries)
          {
            if (pe.pin_policy == pin_policy)
              {
                return pe.value;
              }
          }
        throw new IOException ("PIN policy missing!");
      }
  }
