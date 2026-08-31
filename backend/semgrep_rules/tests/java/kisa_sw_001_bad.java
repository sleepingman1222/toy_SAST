import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class SqlInjectionBad {

    public void search(
        HttpServletRequest request,
        Statement statement
    ) throws Exception {

        String id =
            request.getParameter("id");

        String query =
            "SELECT * FROM users WHERE id = "
            + id;

        statement.executeQuery(
            query
        );
    }
}