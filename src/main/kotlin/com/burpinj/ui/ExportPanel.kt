package com.burpinj.ui

import com.burpinj.engine.JobResult
import java.awt.*
import java.io.File
import java.io.Writer
import java.util.Base64
import javax.swing.*

/** Exports scan results to several formats with optional file splitting. */
class ExportPanel(private val resultsProvider: () -> List<JobResult>) : JPanel(GridBagLayout()) {

    private val formats = arrayOf("JSONL", "JSON", "CSV", "HTML report", "Markdown", "SARIF")
    private val formatBox = JComboBox(formats)
    private val includeReqRes = JCheckBox("Include request / response bytes (base64)", false)
    private val onlyHits = JCheckBox("Only rows above confidence threshold", false)
    private val thresholdSpinner = JSpinner(SpinnerNumberModel(0.5, 0.0, 1.0, 0.05)).apply {
        preferredSize = Dimension(80, preferredSize.height)
        (editor as? JSpinner.NumberEditor)?.textField?.columns = 5
    }
    private val splitCheck = JCheckBox("Split output when a file exceeds", true)
    private val splitSize = JSpinner(SpinnerNumberModel(50, 1, 10_000, 1)).apply {
        preferredSize = Dimension(80, preferredSize.height)
    }
    private val splitUnit = JComboBox(arrayOf("MB", "KB", "rows"))
    private val pathField = JTextField(24)
    private val browseBtn = JButton("Browse…")
    private val exportBtn = JButton("Export now").apply {
        font = Theme.h2; foreground = Color.WHITE; background = Theme.accent
        isOpaque = true; isBorderPainted = false
    }
    private val statusLabel = JLabel(" ").apply { foreground = Theme.fgMuted }

    init {
        border = Theme.titled("Export results")
        // Keep the panel from demanding a wide column from the split-pane.
        preferredSize = Dimension(460, 520)
        minimumSize = Dimension(360, 400)

        val c = GridBagConstraints().apply {
            insets = Insets(4, 8, 4, 8); anchor = GridBagConstraints.WEST
        }

        c.gridx = 0; c.gridy = 0; add(JLabel("Format:"), c)
        c.gridx = 1; c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        add(formatBox, c); c.weightx = 0.0; c.fill = GridBagConstraints.NONE

        c.gridx = 0; c.gridy = 1; c.gridwidth = 2
        add(includeReqRes, c); c.gridwidth = 1

        c.gridy = 2; c.gridx = 0; c.gridwidth = 2
        add(onlyHits, c); c.gridwidth = 1

        c.gridy = 3
        c.gridx = 0; add(JLabel("Confidence threshold:"), c)
        c.gridx = 1; add(thresholdSpinner, c)

        c.gridy = 4; c.gridx = 0; c.gridwidth = 2
        c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        add(JSeparator(), c); c.weightx = 0.0; c.fill = GridBagConstraints.NONE
        c.gridwidth = 1

        c.gridy = 5; c.gridx = 0; c.gridwidth = 2
        add(splitCheck, c); c.gridwidth = 1

        c.gridy = 6; c.gridx = 0; add(JLabel("Split size:"), c)
        c.gridx = 1
        val splitRow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
            add(splitSize); add(splitUnit)
        }
        add(splitRow, c)

        c.gridy = 7; c.gridx = 0; c.gridwidth = 2
        c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        add(JSeparator(), c); c.weightx = 0.0; c.fill = GridBagConstraints.NONE
        c.gridwidth = 1

        c.gridy = 8; c.gridx = 0; add(JLabel("Output file:"), c)
        c.gridx = 1
        // Wrap field in a fixed-width container so a long path cannot widen the whole panel.
        val pathRow = JPanel(BorderLayout(4, 0)).apply {
            add(pathField, BorderLayout.CENTER)
            add(browseBtn, BorderLayout.EAST)
            preferredSize = Dimension(300, pathField.preferredSize.height)
        }
        c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        add(pathRow, c); c.weightx = 0.0; c.fill = GridBagConstraints.NONE

        c.gridy = 9; c.gridx = 1
        add(exportBtn, c)

        c.gridy = 10; c.gridx = 0; c.gridwidth = 2
        c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        add(statusLabel, c)

        c.gridy = 11; c.gridx = 0; c.gridwidth = 2
        c.fill = GridBagConstraints.BOTH; c.weighty = 1.0
        val hint = JTextArea("""
            JSONL    — one JSON object per line.
            JSON     — single array of objects (easy to feed into jq / pandas).
            CSV      — flat triage table (no signals / no bodies).
            HTML     — self-contained styled report (shareable).
            Markdown — pentest-report friendly summary.
            SARIF    — standard static-analysis format (GitHub / IDE consumable).

            Fields: id, class, position_labels, payloads, status, length,
            time_ms, signals{}, confidence (+ request_b64 / response_b64 when
            enabled). Only JSONL / JSON / SARIF carry the full signal object
            and raw bytes.

            Split: a new file is started whenever the current one exceeds the
            configured size (MB/KB) or row count — files are suffixed .part1,
            .part2, … HTML and SARIF are single-document formats and are NOT
            split regardless of this setting.
        """.trimIndent()).apply {
            isEditable = false; lineWrap = true; wrapStyleWord = true
            foreground = Theme.fgMuted
            background = this@ExportPanel.background
            border = BorderFactory.createEmptyBorder(6, 2, 2, 2)
            font = Font("Segoe UI", Font.PLAIN, 11)
        }
        add(hint, c)

        browseBtn.addActionListener {
            val chooser = JFileChooser()
            chooser.selectedFile = File(defaultFilename())
            if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                pathField.text = chooser.selectedFile.absolutePath
            }
        }
        formatBox.addActionListener { syncSplitAvailability() }
        exportBtn.addActionListener { runExport() }
        syncSplitAvailability()
    }

    private fun format(): String = formatBox.selectedItem as String
    private fun isSingleDoc(): Boolean = format() == "HTML report" || format() == "SARIF"

    private fun syncSplitAvailability() {
        val single = isSingleDoc()
        splitCheck.isEnabled = !single
        splitSize.isEnabled = !single
        splitUnit.isEnabled = !single
    }

    private fun defaultFilename(): String {
        val ts = java.time.LocalDateTime.now().toString().replace(":", "-").substringBefore(".")
        val ext = when (format()) {
            "JSONL" -> "jsonl"
            "JSON" -> "json"
            "CSV" -> "csv"
            "HTML report" -> "html"
            "Markdown" -> "md"
            "SARIF" -> "sarif.json"
            else -> "txt"
        }
        return "burp-injection-$ts.$ext"
    }

    private fun runExport() {
        val raw = resultsProvider()
        if (raw.isEmpty()) { statusLabel.text = "No results to export."; return }
        val rows = if (onlyHits.isSelected) {
            val t = (thresholdSpinner.value as Number).toDouble()
            raw.filter { it.confidence >= t }
        } else raw
        if (rows.isEmpty()) { statusLabel.text = "No rows passed the threshold."; return }

        var pathText = pathField.text.trim()
        if (pathText.isEmpty()) {
            pathText = File(System.getProperty("user.home"), defaultFilename()).absolutePath
            pathField.text = pathText
        }
        val target = File(pathText)
        target.parentFile?.mkdirs()

        try {
            val produced = when (format()) {
                "HTML report" -> writeSingle(rows, target, "html") { rs, w -> writeHtml(rs, w) }
                "SARIF"       -> writeSingle(rows, target, "sarif.json") { rs, w -> writeSarif(rs, w) }
                "JSON"        -> writeJsonArray(rows, target)
                "Markdown"    -> writeSingle(rows, target, "md") { rs, w -> writeMarkdown(rs, w) }
                "CSV"         -> writeLineBased(rows, target, "csv")
                else          -> writeLineBased(rows, target, "jsonl")
            }
            statusLabel.text = "Exported ${rows.size} rows → ${produced.size} file(s): " +
                produced.joinToString(", ") { it.name }
        } catch (t: Throwable) {
            statusLabel.text = "Export failed: ${t.message}"
        }
    }

    private fun splitLimits(): Pair<Long, Int> {
        if (!splitCheck.isSelected) return Pair(Long.MAX_VALUE, Int.MAX_VALUE)
        val n = (splitSize.value as Number).toInt()
        return when (splitUnit.selectedItem as String) {
            "MB" -> Pair(n * 1024L * 1024L, Int.MAX_VALUE)
            "KB" -> Pair(n * 1024L, Int.MAX_VALUE)
            else -> Pair(Long.MAX_VALUE, n)
        }
    }

    private fun writeSingle(rows: List<JobResult>, target: File, defExt: String,
                             body: (List<JobResult>, Writer) -> Unit): List<File> {
        val ext = target.extension.ifBlank { defExt }
        val out = File(target.parentFile ?: File("."), "${target.nameWithoutExtension}.$ext")
        out.bufferedWriter(Charsets.UTF_8).use { body(rows, it) }
        return listOf(out)
    }

    /** JSON array: splits across .part files on the row-count path only (array-per-file is still valid JSON). */
    private fun writeJsonArray(rows: List<JobResult>, target: File): List<File> {
        val (_, maxRows) = splitLimits()
        val chunks = if (maxRows == Int.MAX_VALUE) listOf(rows) else rows.chunked(maxRows)
        val produced = mutableListOf<File>()
        val base = target.nameWithoutExtension
        val ext = target.extension.ifBlank { "json" }
        val parent = target.parentFile ?: File(".")
        val splitting = chunks.size > 1
        chunks.forEachIndexed { idx, chunk ->
            val name = if (splitting) "$base.part${idx + 1}.$ext" else "$base.$ext"
            val f = File(parent, name)
            f.bufferedWriter(Charsets.UTF_8).use { w ->
                w.write("[\n")
                chunk.forEachIndexed { i, r ->
                    w.write(toJson(r, includeReqRes.isSelected))
                    if (i < chunk.size - 1) w.write(",")
                    w.write("\n")
                }
                w.write("]\n")
            }
            produced.add(f)
        }
        return produced
    }

    private fun writeLineBased(rows: List<JobResult>, target: File, defExt: String): List<File> {
        val (maxBytes, maxRows) = splitLimits()
        val produced = mutableListOf<File>()
        val baseName = target.nameWithoutExtension
        val ext = target.extension.ifBlank { defExt }
        val parent = target.parentFile ?: File(".")
        var partIdx = 0
        var writer: Writer? = null
        var currentBytes = 0L
        var currentRows = 0
        val splitting = (maxBytes != Long.MAX_VALUE || maxRows != Int.MAX_VALUE)
        val isCsv = defExt == "csv"

        fun openNext() {
            writer?.close()
            partIdx++
            val name = if (splitting) "$baseName.part$partIdx.$ext" else "$baseName.$ext"
            val f = File(parent, name)
            writer = f.bufferedWriter(Charsets.UTF_8)
            currentBytes = 0; currentRows = 0
            produced.add(f)
            if (isCsv) {
                val header = csvHeader(includeReqRes.isSelected) + "\n"
                writer!!.write(header)
                currentBytes += header.toByteArray(Charsets.UTF_8).size
            }
        }

        openNext()
        for (r in rows) {
            val line = (if (isCsv) toCsv(r, includeReqRes.isSelected) else toJson(r, includeReqRes.isSelected)) + "\n"
            val bytes = line.toByteArray(Charsets.UTF_8)
            if ((currentBytes + bytes.size > maxBytes || currentRows + 1 > maxRows) && currentRows > 0) {
                openNext()
            }
            writer!!.write(line)
            currentBytes += bytes.size
            currentRows++
        }
        writer?.close()
        return produced
    }

    private fun csvHeader(reqRes: Boolean): String {
        val base = "id,class,positions,payloads,status,length,time_ms,confidence"
        return if (reqRes) "$base,request_b64,response_b64" else base
    }

    private fun toCsv(r: JobResult, reqRes: Boolean): String {
        val sb = StringBuilder()
        sb.append(r.id).append(',')
        sb.append(csv(r.klass.label)).append(',')
        sb.append(csv(r.positionLabels.joinToString("|"))).append(',')
        sb.append(csv(r.payloads.joinToString("|"))).append(',')
        sb.append(r.response?.statusCode() ?: 0).append(',')
        sb.append(r.response?.body()?.length() ?: 0).append(',')
        sb.append(r.durationMs).append(',')
        sb.append(String.format(java.util.Locale.ROOT, "%.3f", r.confidence))
        if (reqRes) {
            sb.append(',').append(b64(r.request.toByteArray().bytes))
            sb.append(',').append(b64(r.response?.toByteArray()?.bytes ?: ByteArray(0)))
        }
        return sb.toString()
    }

    private fun csv(s: String): String {
        val needsQuote = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r')
        return if (!needsQuote) s else "\"" + s.replace("\"", "\"\"") + "\""
    }

    private fun toJson(r: JobResult, reqRes: Boolean): String {
        val sb = StringBuilder("{")
        sb.append("\"id\":").append(r.id)
        sb.append(",\"class\":").append(jstr(r.klass.label))
        sb.append(",\"positions\":").append(jarr(r.positionLabels))
        sb.append(",\"payloads\":").append(jarr(r.payloads))
        sb.append(",\"status\":").append(r.response?.statusCode() ?: 0)
        sb.append(",\"length\":").append(r.response?.body()?.length() ?: 0)
        sb.append(",\"time_ms\":").append(r.durationMs)
        sb.append(",\"confidence\":").append(String.format(java.util.Locale.ROOT, "%.3f", r.confidence))
        sb.append(",\"signals\":{")
        sb.append("\"status_changed\":").append(r.signal.statusChanged)
        sb.append(",\"length_delta\":").append(r.signal.lengthDelta)
        sb.append(",\"reflected\":").append(r.signal.reflected)
        sb.append(",\"reflection_context\":").append(jstr(r.signal.reflectionContext ?: ""))
        sb.append(",\"reflection_active\":").append(r.signal.reflectionActive)
        sb.append(",\"error_matches\":").append(jarr(r.signal.errorMatches))
        sb.append(",\"math_hit\":").append(r.signal.mathHit)
        sb.append(",\"sensitive_hit\":").append(r.signal.sensitiveHit)
        sb.append(",\"auth_success_hit\":").append(r.signal.authSuccessHit)
        sb.append(",\"timing_anomaly\":").append(r.signal.timingAnomaly)
        sb.append("}")
        if (r.error != null) sb.append(",\"error\":").append(jstr(r.error))
        if (reqRes) {
            sb.append(",\"request_b64\":").append(jstr(b64(r.request.toByteArray().bytes)))
            sb.append(",\"response_b64\":").append(jstr(b64(r.response?.toByteArray()?.bytes ?: ByteArray(0))))
        }
        sb.append("}")
        return sb.toString()
    }

    // ---- HTML report ----
    private fun writeHtml(rows: List<JobResult>, w: Writer) {
        w.write("""<!doctype html><html><head><meta charset="utf-8"><title>Burp Injection Scanner report</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;background:#1e1e1e;color:#ddd;margin:20px}
 h1{color:#ff8c42;margin:0 0 4px 0}
 .meta{color:#888;margin-bottom:16px}
 table{border-collapse:collapse;width:100%;font-size:12px}
 th,td{border:1px solid #333;padding:4px 6px;vertical-align:top;text-align:left}
 th{background:#2a2a2a;color:#ff8c42;position:sticky;top:0}
 tr.hit{background:#2b1e1e}
 .bar{display:inline-block;height:10px;background:#444;width:80px;position:relative;border-radius:2px}
 .bar>span{display:block;height:100%;background:#ff8c42;border-radius:2px}
 .mono{font-family:Consolas,monospace;font-size:11px;white-space:pre-wrap;word-break:break-all}
 .pill{display:inline-block;padding:1px 6px;border-radius:9px;background:#333;color:#ff8c42;font-size:11px}
</style></head><body>""")
        w.write("<h1>Burp Injection Scanner — report</h1>")
        w.write("<div class='meta'>Generated " + hesc(java.time.LocalDateTime.now().toString()) +
                " · ${rows.size} rows</div>")
        w.write("<table><thead><tr><th>#</th><th>Class</th><th>Positions</th><th>Payload</th>" +
                "<th>Status</th><th>Len</th><th>Time (ms)</th><th>Signals</th><th>Confidence</th></tr></thead><tbody>")
        for (r in rows) {
            val hit = if (r.confidence >= 0.5) " class='hit'" else ""
            val pct = (r.confidence * 100).toInt()
            w.write("<tr$hit><td>${r.id}</td>")
            w.write("<td><span class='pill'>" + hesc(r.klass.label) + "</span></td>")
            w.write("<td class='mono'>" + hesc(r.positionLabels.joinToString(", ")) + "</td>")
            w.write("<td class='mono'>" + hesc(r.payloads.joinToString(" | ").take(400)) + "</td>")
            w.write("<td>${r.response?.statusCode() ?: 0}</td>")
            w.write("<td>${r.response?.body()?.length() ?: 0}</td>")
            w.write("<td>${r.durationMs}</td>")
            w.write("<td class='mono'>" + hesc(signalSummary(r)) + "</td>")
            w.write("<td><span class='bar'><span style='width:${pct}%'></span></span> $pct%</td>")
            w.write("</tr>")
        }
        w.write("</tbody></table></body></html>")
    }

    private fun signalSummary(r: JobResult): String {
        val bits = mutableListOf<String>()
        if (r.signal.errorMatches.isNotEmpty()) bits += "err"
        if (r.signal.mathHit) bits += "math"
        if (r.signal.sensitiveHit) bits += "sens"
        if (r.signal.reflected) bits += "refl:${r.signal.reflectionContext ?: "?"}"
        if (r.signal.timingAnomaly) bits += "slow"
        if (r.signal.statusChanged) bits += "status"
        if (kotlin.math.abs(r.signal.lengthDelta) > 50) bits += "Δlen=${r.signal.lengthDelta}"
        if (r.error != null) bits += "ERR"
        return bits.joinToString(" · ")
    }

    private fun hesc(s: String): String = s
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;")

    // ---- Markdown ----
    private fun writeMarkdown(rows: List<JobResult>, w: Writer) {
        w.write("# Burp Injection Scanner — report\n\n")
        w.write("_Generated ${java.time.LocalDateTime.now()} · ${rows.size} rows_\n\n")
        w.write("| # | Class | Positions | Payload | Status | Len | Time (ms) | Signals | Conf |\n")
        w.write("|---|---|---|---|---|---|---|---|---|\n")
        for (r in rows) {
            fun esc(s: String) = s.replace("|", "\\|").replace("\n", " ")
            w.write("| ${r.id} | ${esc(r.klass.label)} | ${esc(r.positionLabels.joinToString(","))} |")
            w.write(" `${esc(r.payloads.joinToString(" | ").take(200))}` |")
            w.write(" ${r.response?.statusCode() ?: 0} | ${r.response?.body()?.length() ?: 0} |")
            w.write(" ${r.durationMs} | ${esc(signalSummary(r))} |")
            w.write(" ${String.format(java.util.Locale.ROOT, "%.2f", r.confidence)} |\n")
        }
    }

    // ---- SARIF 2.1.0 ----
    private fun writeSarif(rows: List<JobResult>, w: Writer) {
        val sb = StringBuilder()
        sb.append("{\"version\":\"2.1.0\",")
        sb.append("\"\$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",")
        sb.append("\"runs\":[{")
        sb.append("\"tool\":{\"driver\":{\"name\":\"burp-injection-scanner\",\"informationUri\":\"https://portswigger.net\",\"rules\":[")
        val classes = rows.map { it.klass.label }.distinct()
        classes.forEachIndexed { i, cls ->
            if (i > 0) sb.append(',')
            sb.append("{\"id\":").append(jstr(cls))
              .append(",\"shortDescription\":{\"text\":").append(jstr("$cls injection")).append("}}")
        }
        sb.append("]}},\"results\":[")
        rows.forEachIndexed { i, r ->
            if (i > 0) sb.append(',')
            val level = when {
                r.confidence >= 0.75 -> "error"
                r.confidence >= 0.5  -> "warning"
                else                  -> "note"
            }
            val url = try { r.request.url().toString() } catch (_: Throwable) { "" }
            sb.append("{\"ruleId\":").append(jstr(r.klass.label))
              .append(",\"level\":").append(jstr(level))
              .append(",\"message\":{\"text\":")
              .append(jstr("Payload=" + r.payloads.joinToString(" | ").take(200) +
                          " · signals=" + signalSummary(r) +
                          " · confidence=" + String.format(java.util.Locale.ROOT, "%.2f", r.confidence)))
              .append("},\"properties\":{\"confidence\":").append(String.format(java.util.Locale.ROOT, "%.3f", r.confidence))
              .append(",\"positions\":").append(jarr(r.positionLabels))
              .append("},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":")
              .append(jstr(url)).append("}}}]}")
        }
        sb.append("]}]}")
        w.write(sb.toString())
    }

    private fun jstr(s: String): String {
        val sb = StringBuilder("\"")
        for (ch in s) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (ch.code < 0x20) sb.append(String.format("\\u%04x", ch.code)) else sb.append(ch)
            }
        }
        sb.append("\"")
        return sb.toString()
    }

    private fun jarr(xs: List<String>): String =
        xs.joinToString(",", "[", "]") { jstr(it) }

    private fun b64(bytes: ByteArray): String =
        Base64.getEncoder().encodeToString(bytes)
}
