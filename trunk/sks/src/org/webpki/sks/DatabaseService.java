package org.webpki.sks;

import java.sql.Connection;
import java.sql.SQLException;

public interface DatabaseService 
  {
    public Connection getDatabaseConnection () throws SQLException;
  }
