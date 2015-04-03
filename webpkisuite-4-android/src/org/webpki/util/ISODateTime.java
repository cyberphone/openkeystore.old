/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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
package org.webpki.util;

import java.io.IOException;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

/**
 * Useful functions for ISO time.
 */
public class ISODateTime
  {
    private ISODateTime () {}  // No instantiation please

    /**
     * Parse <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code> type:
     * 
     *   _date       = ["-"] 2*C 2Y "-" 2M "-" 2D
     *   _time       = 2h ":" 2m ":" 2s ["." 1*s]
     *   _timeZone   = "Z" / ("+" / "-" 2h ":" 2m)
     *   dateTime    = _date "T" _time [_timeZone]
     *   
     * @param s String to be parsed
     * @return GregorianCalendar
     * @throws IOException If anything unexpected is found...
     */
    public static GregorianCalendar parseDateTime (String s) throws IOException
      {
        GregorianCalendar gc = new GregorianCalendar ();
        gc.clear ();
        
        String t = s;
        int i;

        if(t.startsWith ("-"))
          {
            gc.set (GregorianCalendar.ERA, GregorianCalendar.BC);
            gc.set (GregorianCalendar.YEAR, Integer.parseInt (t.substring (1, i = t.indexOf("-", 1))));
          }
        else
          {
            gc.set (GregorianCalendar.ERA, GregorianCalendar.AD);
            gc.set (GregorianCalendar.YEAR, Integer.parseInt (t.substring (0, i = t.indexOf ("-"))));
          }
        t = t.substring (i+1);

        // Check delimiters (whos positions are now known).
        if (t.charAt(2) != '-' || t.charAt(5) != 'T' ||
            t.charAt(8) != ':' || t.charAt(11) != ':')
          throw new IOException ("Malformed dateTime (" + s + ").");

        gc.set (GregorianCalendar.MONTH, Integer.parseInt (t.substring (0,2)) - 1);
        t = t.substring (3);

        gc.set (GregorianCalendar.DAY_OF_MONTH, Integer.parseInt (t.substring (0,2)));
        t = t.substring (3);

        gc.set (GregorianCalendar.HOUR_OF_DAY, Integer.parseInt (t.substring (0,2)));
        t = t.substring (3);

        gc.set (GregorianCalendar.MINUTE, Integer.parseInt (t.substring (0,2)));
        t = t.substring (3);

        gc.set (GregorianCalendar.SECOND, Integer.parseInt(t.substring (0,2)));
        t = t.substring (2);
            
        // Find time zone info.
        if (t.endsWith ("Z"))
          {
            gc.setTimeZone (TimeZone.getTimeZone("UTC"));
            t = t.substring (0, t.length() - 1);
          }
        else if ((i = t.indexOf ("+")) != -1 || (i = t.indexOf ("-")) != -1)
          {
            if (t.charAt (t.length() - 3) != ':')
              throw new IOException ("Malformed dateTime (" + s + ").");
              
            int tzHour = Integer.parseInt(t.substring (t.charAt(i) == '+' ? i + 1 : i, t.length() - 3)),
                tzMinute = Integer.parseInt(t.substring (t.length() - 2));
            gc.setTimeZone (new SimpleTimeZone (((60 * tzHour) + tzMinute) * 60 * 1000, ""));

            t = t.substring (0, i);
          }
        else
          {
            gc.setTimeZone (TimeZone.getTimeZone("UTC"));
          }

        if (t.length() > 0)
          {
            // Milliseconds.
            if(t.charAt(0) != '.' || t.length () < 2)
              throw new IOException ("Malformed dateTime (" + s + ").");

            t = t.substring (1);

            // We can only handle (exactly) millisecond precision.
            gc.set (GregorianCalendar.MILLISECOND, Integer.parseInt ((t + "000").substring (0, 3)));

            // Round up when necessary.
            if (t.length() > 3 && t.charAt(3) > '4')
              {
                gc.add (GregorianCalendar.MILLISECOND, 1);
              }
          }
        return gc;
      }

    public static String formatDateTime (Date t, boolean force_utc)
      {
        GregorianCalendar gc = new GregorianCalendar ();
        gc.setTime (t);
        SimpleDateFormat sdf = new SimpleDateFormat ("yyyy-MM-dd'T'HH:mm:ss");
        if (force_utc)
          {
            sdf.setTimeZone (TimeZone.getTimeZone ("UTC"));
          }
        StringBuffer s = new StringBuffer (sdf.format (t));
        
        int tzo = force_utc ? 0 : (gc.get(Calendar.ZONE_OFFSET) + gc.get(Calendar.DST_OFFSET)) / (60 * 1000);
        
        if (tzo > 0)
          {
            int tzh = tzo / 60, tzm = tzo % 60;
            s.append (tzh < 10 ? "+0" : "+").append(tzh).append(tzm < 10 ? ":0" : ":").append(tzm);
          }
        else if (tzo < 0)
          {
            int tzh = (-tzo) / 60, tzm = (-tzo) % 60;
            s.append (tzh < 10 ? "-0" : "-").append(tzh).append(tzm < 10 ? ":0" : ":").append(tzm);
          }
        else
          {
            s.append ("Z");
          }

        return s.toString ();
      }
  }
