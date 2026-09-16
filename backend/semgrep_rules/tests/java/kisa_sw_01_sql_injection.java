import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

class kisa_sw_01_sql_injection {

    ResultSet unsafeConcat(
        HttpServletRequest request,
        Statement statement
    ) throws Exception {
        String userId =
            request.getParameter("id");

        // ruleid: kisa.sw01.java.jdbc-string-built-query
        return statement.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }


    ResultSet unsafeIntermediate(
        HttpServletRequest request,
        Statement statement
    ) throws Exception {
        String username =
            request.getParameter("username");

        String sql =
            "SELECT * FROM users WHERE username = '" + username + "'";

        String copiedSql =
            sql;

        // ruleid: kisa.sw01.java.jdbc-string-built-query
        return statement.executeQuery(copiedSql);
    }


    PreparedStatement unsafeDynamicPreparedStatement(
        HttpServletRequest request,
        Connection connection
    ) throws Exception {
        String column =
            request.getParameter("column");

        String sql =
            "SELECT " + column + " FROM users";

        // ruleid: kisa.sw01.java.jdbc-string-built-query
        return connection.prepareStatement(sql);
    }


    Object unsafeJdbcTemplate(
        HttpServletRequest request,
        Object jdbcTemplate
    ) {
        String name =
            request.getParameter("name");

        String sql =
            "SELECT * FROM users WHERE name = '" + name + "'";

        // ruleid: kisa.sw01.java.jdbc-string-built-query
        return ((org.springframework.jdbc.core.JdbcTemplate) jdbcTemplate).queryForList(sql);
    }


    Object unsafeNativeQuery(
        HttpServletRequest request,
        EntityManager entityManager
    ) {
        String orderBy =
            request.getParameter("sort");

        String sql =
            "SELECT * FROM users ORDER BY " + orderBy;

        // ruleid: kisa.sw01.java.jdbc-string-built-query
        return entityManager.createNativeQuery(sql);
    }


    ResultSet safePreparedBinding(
        HttpServletRequest request,
        Connection connection
    ) throws Exception {
        String userId =
            request.getParameter("id");

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


    ResultSet safeHardcodedStatement(
        Statement statement
    ) throws Exception {
        // ok: kisa.sw01.java.jdbc-string-built-query
        return statement.executeQuery("SELECT id, name FROM users");
    }


    Object safeJdbcTemplateBinding(
        HttpServletRequest request,
        org.springframework.jdbc.core.JdbcTemplate jdbcTemplate
    ) {
        String name =
            request.getParameter("name");

        // ok: kisa.sw01.java.jdbc-string-built-query
        return jdbcTemplate.queryForList(
            "SELECT * FROM users WHERE name = ?",
            name
        );
    }
}
