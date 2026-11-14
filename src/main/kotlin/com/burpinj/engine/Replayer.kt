package com.burpinj.engine

import burp.api.montoya.http.message.requests.HttpRequest
import java.nio.charset.StandardCharsets

/** Applies payload substitutions into insertion points, producing a new HttpRequest. */
object Replayer {

    /**
     * Rewrites `base` so that each insertion point's byte range is replaced by the
     * payload at the same index in `payloads`. Positions must be disjoint and in
     * ascending order.
     */
    fun withPayloads(
        base: HttpRequest,
        positions: List<InsertionPoint>,
        payloads: List<String>
    ): HttpRequest {
        require(positions.size == payloads.size) { "positions/payloads size mismatch" }
        val raw = base.toByteArray().bytes
        val out = ByteArray(estimateSize(raw.size, positions, payloads))
        var srcIdx = 0
        var dstIdx = 0
        val sorted = positions.zip(payloads).sortedBy { it.first.start }
        for ((pos, payload) in sorted) {
            val before = pos.start - srcIdx
            System.arraycopy(raw, srcIdx, out, dstIdx, before)
            dstIdx += before
            val payloadBytes = payload.toByteArray(StandardCharsets.ISO_8859_1)
            System.arraycopy(payloadBytes, 0, out, dstIdx, payloadBytes.size)
            dstIdx += payloadBytes.size
            srcIdx = pos.end
        }
        val tail = raw.size - srcIdx
        System.arraycopy(raw, srcIdx, out, dstIdx, tail)
        dstIdx += tail
        val trimmed = out.copyOf(dstIdx)
        return HttpRequest.httpRequest(base.httpService(), burp.api.montoya.core.ByteArray.byteArray(*trimmed))
    }

    private fun estimateSize(
        baseSize: Int,
        positions: List<InsertionPoint>,
        payloads: List<String>
    ): Int {
        var size = baseSize
        positions.forEachIndexed { i, p ->
            size += payloads[i].length - p.length
        }
        return size.coerceAtLeast(baseSize)
    }
}
