import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

class KisaSw01SqlInjection {

    ResultSet unsafe(
        Statement statement,
        String userId
    ) throws Exception {

        // ruleid: kisa.sw01.java.jdbc-string-built-query
        return statement.executeQuery(
            "SELECT * FROM users WHERE id = " + userId
        );
    }

    ResultSet safe(
        Connection connection,
        String userId
    ) throws Exception {

        PreparedStatement statement =
            connection.prepareStatement(
                "SELECT * FROM users WHERE id = ?"
            );

        statement.setString(
            1,
            userId
        );

        // ok: kisa.sw01.java.jdbc-string-built-query
        return statement.executeQuery();
    }
}
