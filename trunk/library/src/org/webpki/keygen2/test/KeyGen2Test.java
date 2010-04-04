package org.webpki.keygen2.test;

import java.util.Vector;
import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

public class KeyGen2Test
  {
    @Before
    public void fuck ()
      {
        System.out.println ("Hej");
      }
    @Test
    public void testEmptyCollection() {
      Vector<String> collection = new Vector<String>();
        assertTrue(collection.isEmpty());
    }

  }
