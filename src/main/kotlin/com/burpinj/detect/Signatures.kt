package com.burpinj.detect

object Signatures {
    val sqlErrors: List<Regex> = listOf(
        Regex("SQL syntax.*MySQL", RegexOption.IGNORE_CASE),
        Regex("Warning.*mysql_", RegexOption.IGNORE_CASE),
        Regex("valid MySQL result", RegexOption.IGNORE_CASE),
        Regex("PostgreSQL.*ERROR", RegexOption.IGNORE_CASE),
        Regex("Warning.*pg_", RegexOption.IGNORE_CASE),
        Regex("Driver.*SQL[\\- ]Server", RegexOption.IGNORE_CASE),
        Regex("OLE DB.*SQL Server", RegexOption.IGNORE_CASE),
        Regex("Microsoft OLE DB Provider for ODBC Drivers", RegexOption.IGNORE_CASE),
        Regex("Unclosed quotation mark after the character string", RegexOption.IGNORE_CASE),
        Regex("ORA-[0-9]{5}", RegexOption.IGNORE_CASE),
        Regex("Oracle error", RegexOption.IGNORE_CASE),
        Regex("SQLite/JDBCDriver", RegexOption.IGNORE_CASE),
        Regex("SQLITE_ERROR", RegexOption.IGNORE_CASE),
        Regex("SQLSTATE\\[", RegexOption.IGNORE_CASE),
        Regex("you have an error in your SQL syntax", RegexOption.IGNORE_CASE)
    )

    val templateErrors: List<Regex> = listOf(
        Regex("jinja2\\.exceptions", RegexOption.IGNORE_CASE),
        Regex("TemplateSyntaxError", RegexOption.IGNORE_CASE),
        Regex("freemarker\\.core\\.ParseException", RegexOption.IGNORE_CASE),
        Regex("org\\.apache\\.velocity", RegexOption.IGNORE_CASE),
        Regex("Twig_Error", RegexOption.IGNORE_CASE),
        Regex("SmartyException", RegexOption.IGNORE_CASE)
    )

    val xxeHints: List<Regex> = listOf(
        Regex("root:[x*!]:0:0:"),
        Regex("\\[fonts\\]"),
        Regex("DOCTYPE html PUBLIC", RegexOption.IGNORE_CASE)
    )

    val pathHints: List<Regex> = listOf(
        Regex("root:[x*!]:0:0:"),
        Regex("\\[fonts\\]", RegexOption.IGNORE_CASE),
        Regex("\\[extensions\\]", RegexOption.IGNORE_CASE),
        Regex("\\[mci extensions\\]", RegexOption.IGNORE_CASE),
        Regex("; for 16-bit app support", RegexOption.IGNORE_CASE),
        Regex("127\\.0\\.0\\.1\\s+localhost", RegexOption.IGNORE_CASE)
    )

    val ldapErrors: List<Regex> = listOf(
        Regex("javax\\.naming\\.NamingException", RegexOption.IGNORE_CASE),
        Regex("LDAP.*error", RegexOption.IGNORE_CASE),
        Regex("Supplied argument is not a valid ldap", RegexOption.IGNORE_CASE)
    )

    val rceHints: List<Regex> = listOf(
        // Linux
        Regex("uid=\\d+.*gid=\\d+"),
        Regex("root:[x*!]:0:0:"),
        Regex("Linux\\s+[\\w.-]+\\s+\\d+\\.\\d+", RegexOption.IGNORE_CASE),
        // Windows
        Regex("\\bNT AUTHORITY\\\\SYSTEM\\b", RegexOption.IGNORE_CASE),
        Regex("Microsoft Windows \\[Version", RegexOption.IGNORE_CASE),
        Regex("Windows IP Configuration", RegexOption.IGNORE_CASE),
        Regex("Volume in drive [A-Z]", RegexOption.IGNORE_CASE),
        Regex("\\bDirectory of\\b", RegexOption.IGNORE_CASE),
        Regex("Pinging [^ ]+ with \\d+ bytes", RegexOption.IGNORE_CASE),
        Regex("\\[fonts\\]", RegexOption.IGNORE_CASE)
    )

    /** Login-bypass success markers — body indicates the user got in. */
    val authSuccess: List<Regex> = listOf(
        Regex("\\bwelcome[,\\s]+[a-z0-9_.-]+", RegexOption.IGNORE_CASE),
        Regex("\\blogged\\s*in\\b", RegexOption.IGNORE_CASE),
        Regex("\\bsigned\\s*in\\b", RegexOption.IGNORE_CASE),
        Regex("\\bauthenticated\\s+as\\b", RegexOption.IGNORE_CASE),
        Regex("\\bsign\\s*out\\b", RegexOption.IGNORE_CASE),
        Regex("\\blog\\s*out\\b", RegexOption.IGNORE_CASE),
        Regex("\\bdashboard\\b", RegexOption.IGNORE_CASE),
        Regex("\\bmy\\s+account\\b", RegexOption.IGNORE_CASE)
    )

    /** Common failure phrases — presence vetoes an authSuccess match. */
    val authFailure: List<Regex> = listOf(
        Regex("\\binvalid\\s+credentials\\b", RegexOption.IGNORE_CASE),
        Regex("\\bbad\\s+credentials\\b", RegexOption.IGNORE_CASE),
        Regex("\\blogin\\s+failed\\b", RegexOption.IGNORE_CASE),
        Regex("\\baccess\\s+denied\\b", RegexOption.IGNORE_CASE),
        Regex("\\bunauthori[sz]ed\\b", RegexOption.IGNORE_CASE)
    )
}
