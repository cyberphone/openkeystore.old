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

import java.util.regex.Pattern;

/**
 * Useful functions for ISO time.
 */
public class ISODateTime
  {
    private ISODateTime () {}  // No instantiation please
    
    static final Pattern DATE_PATTERN =
        Pattern.compile("(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(\\.\\d{1,3})?([+-]\\d{2}:\\d{2}|Z)");


    /**
     * 
     * Always: YYYY-MM-DDThh:mm:ss
     * Optionally: a '.' followed by 1-3 digits giving millisecond
     * Finally: 'Z' for UTC or an UTC time-zone difference expressed as +hh:mm or -hh:mm
     *   
     * @param dateTime String to be parsed
     * @return GregorianCalendar
     * @throws IOException If anything unexpected is found...
     */
    public static GregorianCalendar parseDateTime (String dateTime) throws IOException
      {
        if (!DATE_PATTERN.matcher(dateTime).matches ())
          {
            throw new IOException("DateTime syntax error: " + dateTime);
          }

        GregorianCalendar gc = new GregorianCalendar ();
        gc.clear ();
        
        gc.set (GregorianCalendar.ERA, GregorianCalendar.AD);
        gc.set (GregorianCalendar.YEAR, Integer.parseInt (dateTime.substring (0, 4)));
 
        gc.set (GregorianCalendar.MONTH, Integer.parseInt (dateTime.substring (5,7)) - 1);

        gc.set (GregorianCalendar.DAY_OF_MONTH, Integer.parseInt (dateTime.substring (8,10)));
 
        gc.set (GregorianCalendar.HOUR_OF_DAY, Integer.parseInt (dateTime.substring (11,13)));

        gc.set (GregorianCalendar.MINUTE, Integer.parseInt (dateTime.substring (14,16)));

        gc.set (GregorianCalendar.SECOND, Integer.parseInt(dateTime.substring (17,19)));
        
        String milliSeconds = null;
        
        // Find time zone info.
        if (dateTime.endsWith("Z"))
          {
            gc.setTimeZone (TimeZone.getTimeZone("UTC"));
            milliSeconds = dateTime.substring (19, dateTime.length() - 1);
          }
        else
          {
            int factor = 60 * 1000;
            int i = dateTime.indexOf ('+');
            if (i < 0) {
              i = dateTime.lastIndexOf ('-');
              factor = -factor;
            }
            milliSeconds = dateTime.substring (19, i);
            int tzHour = Integer.parseInt(dateTime.substring (++i, i + 2)),
                tzMinute = Integer.parseInt(dateTime.substring (i + 3, i + 5));
            gc.setTimeZone (new SimpleTimeZone (((60 * tzHour) + tzMinute) * factor, ""));
          }
        if (milliSeconds.length() > 0)
          {
            // Milliseconds.
            gc.set (GregorianCalendar.MILLISECOND, 
                    Integer.parseInt ((milliSeconds.substring (1) + "00").substring (0, 3)));
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

