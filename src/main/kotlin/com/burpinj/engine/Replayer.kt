package com.burpinj.engine

import burp.api.montoya.http.message.requests.HttpRequest
import java.nio.charset.StandardCharsets

/** Applies payload substitutions into insertion points, producing a new HttpRequest. */
object Replayer {

    private enum class Ctx { QUERY, FORM_BODY, OTHER }

    /**
     * Rewrites `base` so that each insertion point's byte range is replaced by the
     * payload at the same index in `payloads`. Positions must be disjoint and in
     * ascending order. Payloads inserted into the URL query string or into an
     * application/x-www-form-urlencoded body get minimal percent-encoding so that
     * parser-breaking characters (space, &, =, +, #, ;, %, CR, LF) do not corrupt
     * the surrounding field. JSON / XML / header values are left untouched.
     */
    fun withPayloads(
        base: HttpRequest,
        positions: List<InsertionPoint>,
        payloads: List<String>
    ): HttpRequest {
        require(positions.size == payloads.size) { "positions/payloads size mismatch" }
        val raw = base.toByteArray().bytes

        val headerEnd = findHeaderEnd(raw)
        val firstLineEnd = findLineEnd(raw, 0)
        val isForm = headerContentTypeIsForm(raw, headerEnd)
        val queryStart = findQueryStart(raw, firstLineEnd)

        val sorted = positions.zip(payloads).sortedBy { it.first.start }
        val bytes = java.io.ByteArrayOutputStream(raw.size + 64)
        var src = 0
        for ((pos, payload) in sorted) {
            bytes.write(raw, src, pos.start - src)
            val ctx = classify(pos.start, firstLineEnd, headerEnd, queryStart, isForm)
            val encoded = if (ctx == Ctx.OTHER) payload else minimalFormEncode(payload)
            bytes.write(encoded.toByteArray(StandardCharsets.ISO_8859_1))
            src = pos.end
        }
        bytes.write(raw, src, raw.size - src)
        val arr = bytes.toByteArray()
        return HttpRequest.httpRequest(base.httpService(), burp.api.montoya.core.ByteArray.byteArray(*arr))
    }

    private fun classify(start: Int, firstLineEnd: Int, headerEnd: Int, queryStart: Int, isForm: Boolean): Ctx {
        return when {
            start >= headerEnd && isForm -> Ctx.FORM_BODY
            start < firstLineEnd && queryStart in 0 until start -> Ctx.QUERY
            else -> Ctx.OTHER
        }
    }

    private fun findLineEnd(raw: ByteArray, from: Int): Int {
        var i = from
        while (i < raw.size - 1) {
            if (raw[i] == '\r'.code.toByte() && raw[i + 1] == '\n'.code.toByte()) return i
            i++
        }
        return raw.size
    }

    private fun findHeaderEnd(raw: ByteArray): Int {
        var i = 0
        while (i < raw.size - 3) {
            if (raw[i] == '\r'.code.toByte() && raw[i + 1] == '\n'.code.toByte()
                && raw[i + 2] == '\r'.code.toByte() && raw[i + 3] == '\n'.code.toByte()
            ) return i + 4
            i++
        }
        return raw.size
    }

    private fun findQueryStart(raw: ByteArray, firstLineEnd: Int): Int {
        for (i in 0 until firstLineEnd) {
            if (raw[i] == '?'.code.toByte()) return i
        }
        return -1
    }

    private fun headerContentTypeIsForm(raw: ByteArray, headerEnd: Int): Boolean {
        if (headerEnd <= 0 || headerEnd > raw.size) return false
        val headerBlock = String(raw, 0, headerEnd, StandardCharsets.ISO_8859_1)
        for (line in headerBlock.split("\r\n")) {
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            if (line.substring(0, idx).trim().equals("Content-Type", ignoreCase = true)) {
                val v = line.substring(idx + 1).trim().lowercase()
                return v.startsWith("application/x-www-form-urlencoded")
            }
        }
        return false
    }

    /**
     * Percent-encode just the characters that would break a form field or query
     * parameter if inserted raw. Payloads already URL-encoded upstream (via the
     * UI "URL-encode" option) stay intact because their chars are already %-safe.
     */
    private fun minimalFormEncode(s: String): String {
        val sb = StringBuilder(s.length + 8)
        for (ch in s) {
            when (ch) {
                ' ' -> sb.append("%20")
                '&' -> sb.append("%26")
                '=' -> sb.append("%3D")
                '+' -> sb.append("%2B")
                '#' -> sb.append("%23")
                ';' -> sb.append("%3B")
                '\r' -> sb.append("%0D")
                '\n' -> sb.append("%0A")
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }
}
