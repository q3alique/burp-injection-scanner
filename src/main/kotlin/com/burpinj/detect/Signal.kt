package com.burpinj.detect

import com.burpinj.payloads.PayloadClass

/** Facts about a single response, relative to the baseline. */
data class Signal(
    val statusChanged: Boolean = false,
    val baselineStatus: Short = 0,
    val responseStatus: Short = 0,
    val lengthDelta: Int = 0,
    val timeMs: Long = 0,
    val baselineTimeMs: Long = 0,
    val reflected: Boolean = false,
    val reflectionContext: String? = null,
    val reflectionActive: Boolean = false,        // payload contained real XSS metacharacters and they survived
    val errorMatches: List<String> = emptyList(),
    val mathHit: Boolean = false,                 // SSTI 49 / 7777777
    val sensitiveHit: Boolean = false,            // /etc/passwd, win.ini, uid=…
    val authSuccessHit: Boolean = false,          // SQLi login-bypass: "welcome", "logged in" etc.
    val booleanTruthy: Boolean? = null,           // paired analysis (external)
    val timingAnomaly: Boolean = false            // ≥ ~5s slower than baseline
)

/** Weighted confidence per payload class. */
object Scorer {
    fun score(klass: PayloadClass, s: Signal): Double {
        var score = 0.0
        when (klass) {
            PayloadClass.SQLI -> {
                if (s.errorMatches.isNotEmpty()) score += 0.65
                if (s.timingAnomaly) score += 0.45
                // Auth-bypass pattern: 4xx/5xx baseline flipping to 2xx AND a success keyword in body.
                val baselineWasError = s.baselineStatus in 400..599
                val responseIsOk = s.responseStatus in 200..299
                if (baselineWasError && responseIsOk && s.authSuccessHit) score += 0.80
                else if (baselineWasError && responseIsOk) score += 0.35
                else if (s.authSuccessHit) score += 0.35
                if (s.statusChanged) score += 0.10
                if (Math.abs(s.lengthDelta) > 200) score += 0.10
            }
            PayloadClass.XSS -> {
                // Only count as XSS evidence when the payload carried an active metachar
                // AND survived in the response. Plain-text reflection is near-worthless.
                if (s.reflected && s.reflectionActive) {
                    score += 0.55
                    when (s.reflectionContext) {
                        "html" -> score += 0.25
                        "attr" -> score += 0.20
                        "js"   -> score += 0.30
                    }
                } else if (s.reflected) {
                    score += 0.10
                }
                // Heavy penalty on error pages — common login/400 pages often contain stray `<` or `"` noise.
                if (s.responseStatus in 400..599) score *= 0.4
            }
            PayloadClass.SSTI -> {
                if (s.mathHit) score += 0.80
                if (s.errorMatches.isNotEmpty()) score += 0.30
            }
            PayloadClass.RCE -> {
                if (s.sensitiveHit) score += 0.70
                if (s.timingAnomaly) score += 0.55
            }
            PayloadClass.LDAP -> {
                if (s.errorMatches.isNotEmpty()) score += 0.55
                if (Math.abs(s.lengthDelta) > 200) score += 0.15
            }
            PayloadClass.XXE -> {
                if (s.sensitiveHit) score += 0.80
                if (s.errorMatches.isNotEmpty()) score += 0.25
            }
            PayloadClass.PATH -> {
                if (s.sensitiveHit) score += 0.80
                if (Math.abs(s.lengthDelta) > 200) score += 0.10
            }
            PayloadClass.NOSQLI -> {
                val baselineWasError = s.baselineStatus in 400..599
                val responseIsOk = s.responseStatus in 200..299
                if (baselineWasError && responseIsOk && s.authSuccessHit) score += 0.80
                if (s.statusChanged) score += 0.20
                if (Math.abs(s.lengthDelta) > 500) score += 0.25
                if (s.errorMatches.isNotEmpty()) score += 0.30
                if (s.timingAnomaly) score += 0.45
            }
            PayloadClass.CRLF -> {
                if (s.reflected) score += 0.60
            }
        }
        return score.coerceIn(0.0, 1.0)
    }

    fun analyse(
        klass: PayloadClass,
        baselineBody: String,
        baselineStatus: Short,
        baselineTimeMs: Long,
        responseBody: String,
        responseStatus: Short,
        responseTimeMs: Long,
        payload: String
    ): Signal {
        val reflection = Reflection.find(payload, responseBody)
        val reflectionActive = reflection != null && payloadIsActiveXss(payload)

        val errors = when (klass) {
            PayloadClass.SQLI -> Signatures.sqlErrors
            PayloadClass.SSTI -> Signatures.templateErrors
            PayloadClass.LDAP -> Signatures.ldapErrors
            PayloadClass.XXE  -> Signatures.xxeHints
            else -> emptyList()
        }.filter { it.containsMatchIn(responseBody) }.map { it.pattern }

        val sensitive = when (klass) {
            PayloadClass.RCE  -> Signatures.rceHints
            PayloadClass.PATH -> Signatures.pathHints
            PayloadClass.XXE  -> Signatures.xxeHints
            else -> emptyList()
        }.any { it.containsMatchIn(responseBody) }

        val authHit = (klass == PayloadClass.SQLI || klass == PayloadClass.NOSQLI) &&
            Signatures.authSuccess.any { it.containsMatchIn(responseBody) } &&
            !Signatures.authFailure.any { it.containsMatchIn(responseBody) }

        val mathHit = klass == PayloadClass.SSTI && (
            (payload.contains("7*7") && responseBody.contains("49")) ||
            (payload.contains("7*'7'") && responseBody.contains("7777777"))
        )

        val timingAnomaly = responseTimeMs - baselineTimeMs >= 4500

        return Signal(
            statusChanged = baselineStatus != responseStatus,
            baselineStatus = baselineStatus,
            responseStatus = responseStatus,
            lengthDelta = responseBody.length - baselineBody.length,
            timeMs = responseTimeMs,
            baselineTimeMs = baselineTimeMs,
            reflected = reflection != null,
            reflectionContext = reflection,
            reflectionActive = reflectionActive,
            errorMatches = errors,
            mathHit = mathHit,
            sensitiveHit = sensitive,
            authSuccessHit = authHit,
            timingAnomaly = timingAnomaly
        )
    }

    private fun payloadIsActiveXss(payload: String): Boolean {
        val p = payload.lowercase()
        return p.contains("<script") || p.contains("</script") ||
            p.contains("onerror") || p.contains("onload") || p.contains("onmouseover") ||
            p.contains("onclick") || p.contains("onfocus") ||
            p.contains("<svg") || p.contains("<img") || p.contains("<iframe") ||
            p.contains("<body") || p.contains("<audio") || p.contains("<video") ||
            p.contains("javascript:") || p.contains("alert(") || p.contains("prompt(") ||
            p.contains("confirm(") ||
            // polyglots that break out of attr/js contexts
            (p.contains("\">") && p.contains("<")) ||
            (p.contains("';") && p.contains("<"))
    }
}

object Reflection {
    /** Returns a crude context tag ("html"/"attr"/"js") or null if not reflected.
     *  Requires at least 6 characters of the payload to survive literally. */
    fun find(payload: String, body: String): String? {
        val needle = when {
            payload.length < 6 -> return null
            payload.length <= 48 -> payload
            else -> payload.substring(0, 32)
        }
        if (needle.isBlank()) return null
        val idx = body.indexOf(needle)
        if (idx < 0) return null
        val around = body.substring(maxOf(0, idx - 40), minOf(body.length, idx + needle.length + 40))
        return when {
            around.contains("<script", ignoreCase = true) -> "js"
            Regex("""=\s*["']?[^"'>]*$""").containsMatchIn(around.substringBefore(needle)) -> "attr"
            else -> "html"
        }
    }
}
