package org.webpki.sksimpl.dbemulator;

import java.sql.Connection;
import java.sql.SQLException;

public interface DatabaseService 
  {
    public Connection getDatabaseConnection () throws SQLException;
  }
