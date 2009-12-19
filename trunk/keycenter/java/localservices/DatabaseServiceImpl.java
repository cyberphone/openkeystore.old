package localservices;

import java.sql.Connection;
import java.sql.SQLException;

import org.webpki.sks.DatabaseService;

import misc.ProtectedServlet;

public class DatabaseServiceImpl implements DatabaseService
  {

    public Connection getDatabaseConnection () throws SQLException
      {
        return ProtectedServlet.getDatabaseConnection ();
      }

  }
