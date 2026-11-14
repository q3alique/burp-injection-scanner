package com.burpinj.engine

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.Semaphore
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Bounded-concurrency sender. Fires jobs, delivers results through a callback. */
class Scheduler(
    private val api: MontoyaApi,
    concurrency: Int = 4,
    private val interRequestDelayMs: Long = 0
) {
    private val gate = Semaphore(concurrency)
    private val executor: ThreadPoolExecutor = ThreadPoolExecutor(
        concurrency, concurrency,
        30, TimeUnit.SECONDS,
        LinkedBlockingQueue()
    ).apply { allowCoreThreadTimeOut(true) }

    private val aborted = AtomicBoolean(false)
    private val outstanding = AtomicInteger(0)
    private val submissionsSealed = AtomicBoolean(false)
    @Volatile private var onIdle: (() -> Unit)? = null

    data class Sent(
        val request: HttpRequest,
        val response: HttpResponse?,
        val durationMs: Long,
        val error: String? = null
    )

    fun submit(req: HttpRequest, onDone: (Sent) -> Unit) {
        if (aborted.get()) return
        outstanding.incrementAndGet()
        executor.submit {
            if (aborted.get()) { finishOne(); return@submit }
            gate.acquire()
            try {
                if (interRequestDelayMs > 0) Thread.sleep(interRequestDelayMs)
                val started = System.nanoTime()
                try {
                    val result = api.http().sendRequest(req)
                    val tookMs = (System.nanoTime() - started) / 1_000_000
                    onDone(Sent(req, result.response(), tookMs))
                } catch (t: Throwable) {
                    val tookMs = (System.nanoTime() - started) / 1_000_000
                    onDone(Sent(req, null, tookMs, t.message ?: t::class.simpleName))
                }
            } finally {
                gate.release()
                finishOne()
            }
        }
    }

    private fun finishOne() {
        val left = outstanding.decrementAndGet()
        if (left == 0 && submissionsSealed.get()) {
            onIdle?.invoke()
        }
    }

    /** Call once all submit() calls for a job are done; triggers [onIdle] when the queue drains. */
    fun sealAndWatch(cb: () -> Unit) {
        onIdle = cb
        submissionsSealed.set(true)
        if (outstanding.get() == 0) cb()
    }

    fun abort() {
        aborted.set(true)
        executor.shutdownNow()
        onIdle?.invoke()
    }

    fun shutdown() {
        executor.shutdown()
    }
}
