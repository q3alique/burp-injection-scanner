package com.burpinj.payloads

enum class PayloadClass(val id: String, val label: String) {
    SQLI("sqli", "SQL Injection"),
    XSS("xss", "Cross-Site Scripting"),
    SSTI("ssti", "Server-Side Template Injection"),
    RCE("rce", "Command Injection / RCE"),
    LDAP("ldap", "LDAP Injection"),
    XXE("xxe", "XXE"),
    PATH("path", "Path Traversal"),
    NOSQLI("nosqli", "NoSQL Injection"),
    CRLF("crlf", "CRLF / Header Injection");
}

enum class Phase { DETECTION, DEEP }

enum class TargetOs { ANY, LINUX, WINDOWS }

data class PayloadSet(
    val klass: PayloadClass,
    val phase: Phase,
    val payloads: List<String>,
    val source: String = "built-in"
)

/** Loads payload lists from resources (`/payloads/<class>/<phase>.txt`).
 *  Lines may start with an OS tag `[nix]`, `[win]`, or `[any]` (default any).
 *  The tag is stripped before use, and lines are filtered by [os]. */
object PayloadRepo {

    private val tagRegex = Regex("""^\[(nix|win|any)]\s*""", RegexOption.IGNORE_CASE)

    fun builtIn(klass: PayloadClass, phase: Phase, os: TargetOs = TargetOs.ANY): PayloadSet {
        val name = if (phase == Phase.DETECTION) "probe" else "deep"
        val path = "/payloads/${klass.id}/$name.txt"
        val stream = javaClass.getResourceAsStream(path)
            ?: return PayloadSet(klass, phase, emptyList(), "missing:$path")
        val lines = stream.bufferedReader().readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
        return PayloadSet(klass, phase, filterByOs(lines, os), "built-in")
    }

    fun fromFile(klass: PayloadClass, phase: Phase, path: java.io.File, os: TargetOs = TargetOs.ANY): PayloadSet {
        val lines = path.readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
        return PayloadSet(klass, phase, filterByOs(lines, os), path.absolutePath)
    }

    private fun filterByOs(lines: List<String>, os: TargetOs): List<String> {
        val out = ArrayList<String>(lines.size)
        for (raw in lines) {
            val m = tagRegex.find(raw)
            val tag = m?.groupValues?.get(1)?.lowercase() ?: "any"
            val payload = if (m != null) raw.substring(m.range.last + 1) else raw
            val keep = when (os) {
                TargetOs.ANY -> true
                TargetOs.LINUX -> tag == "any" || tag == "nix"
                TargetOs.WINDOWS -> tag == "any" || tag == "win"
            }
            if (keep) out.add(payload)
        }
        return out
    }
}
