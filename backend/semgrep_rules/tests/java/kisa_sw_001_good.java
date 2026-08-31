import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;

class SqlInjectionGood {

    public void search(
        HttpServletRequest request,
        Connection connection
    ) throws Exception {

        String id =
            request.getParameter("id");

        String query =
            "SELECT * FROM users WHERE id = ?";

        PreparedStatement statement =
            connection.prepareStatement(
                query
            );

        statement.setString(
            1,
            id
        );

        statement.executeQuery();
    }
}