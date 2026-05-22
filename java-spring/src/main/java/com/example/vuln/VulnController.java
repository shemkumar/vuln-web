package com.example.vuln;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.sql.*;
import javax.naming.directory.*;
import javax.naming.*;
import java.util.Hashtable;

@RestController
public class VulnController {
    private static final String DB_URL = "jdbc:mysql://localhost/vulnapp";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "Password123!"; // fake hardcoded secret

    @GetMapping("/java/user/{id}")
    public String getUser(@PathVariable String id) throws Exception {
        // A03 SQL injection.
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT email, ssn FROM users WHERE id=" + id);
        StringBuilder out = new StringBuilder();
        while (rs.next()) {
            out.append(rs.getString("email")).append(":").append(rs.getString("ssn"));
        }
        return out.toString();
    }

    @PostMapping("/java/admin/run")
    public String run(@RequestParam String command) throws Exception {
        // A01 missing admin check and A03 command injection.
        Process p = Runtime.getRuntime().exec(command);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        return br.readLine();
    }

    @GetMapping("/java/ldap")
    public String ldap(@RequestParam String username) throws Exception {
        // A03 LDAP injection-style string concatenation.
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        DirContext ctx = new InitialDirContext(env);
        NamingEnumeration<SearchResult> results = ctx.search("ou=users,dc=example,dc=com", "(uid=" + username + ")", new SearchControls());
        return results.hasMore() ? results.next().getName() : "none";
    }

    @PostMapping("/java/object")
    public String deserialize(@RequestBody byte[] body) throws Exception {
        // A08 unsafe Java deserialization. Removed due to critical security vulnerability.
        // ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body));
        // Object obj = ois.readObject();
        // return obj.toString();
        return "Deserialization of untrusted data is disabled for security reasons.";
    }
}
