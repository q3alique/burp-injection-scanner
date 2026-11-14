package com.burpinj.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpResponseEditor
import com.burpinj.engine.*
import java.awt.*
import javax.swing.*

class MainTab(private val api: MontoyaApi) {

    private val requestEditor: HttpRequestEditor =
        api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
    private val previewRequestEditor: HttpRequestEditor =
        api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
    private val previewResponseEditor: HttpResponseEditor =
        api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)

    private val positions = PositionsPanel()
    private val payloads = PayloadManagerPanel()
    private val results = ResultsTable(api)

    private val pruneCheck = JCheckBox("Context-aware payload pruning (skip irrelevant classes per position)", false)
    private val urlEncCheck = JCheckBox("URL-encode payloads (adds a variant per payload)", false)
    private val doubleUrlEncCheck = JCheckBox("Double URL-encode payloads (adds a variant per payload)", false)
    private val base64EncCheck = JCheckBox("Base64-encode payloads (adds a variant per payload)", false)

    private val attackModeBox = JComboBox(AttackMode.values()).apply {
        renderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                l: JList<*>?, v: Any?, i: Int, s: Boolean, f: Boolean
            ): Component {
                val m = v as AttackMode
                return super.getListCellRendererComponent(l, m.label, i, s, f)
            }
        }
    }
    private val concurrencySpinner = JSpinner(SpinnerNumberModel(4, 1, 32, 1))
    private val delaySpinner = JSpinner(SpinnerNumberModel(0, 0, 5000, 50))
    private val maxRequestsSpinner = JSpinner(SpinnerNumberModel(2000, 10, 50000, 100))

    private val startBtn = JButton("▶  Start").apply {
        font = Theme.h2; foreground = Color.WHITE; background = Theme.accent; isOpaque = true; isBorderPainted = false
    }
    private val stopBtn = JButton("■  Stop").apply { isEnabled = false }
    private val addPosBtn = JButton("Add §§")
    private val statusLabel = JLabel("Ready.").apply { foreground = Theme.fgMuted }

    private var currentBase: HttpRequest? = null
    private var scheduler: Scheduler? = null
    private var jobRunner: JobRunner? = null

    val component: JComponent = buildRoot()

    private fun buildRoot(): JComponent {
        val root = JPanel(BorderLayout())
        root.border = Theme.pad()

        // ---- Header ----
        val header = JPanel(BorderLayout())
        val title = JLabel("Injection Scanner").apply {
            font = Font("Segoe UI", Font.BOLD, 18)
            foreground = Theme.accent
        }
        val subtitle = JLabel("  Detect SQLi · XSS · SSTI · RCE · LDAP · XXE · Path · NoSQLi · CRLF").apply {
            foreground = Theme.fgMuted
        }
        val headerLeft = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        headerLeft.add(title); headerLeft.add(subtitle)
        header.add(headerLeft, BorderLayout.WEST)
        root.add(header, BorderLayout.NORTH)

        // ---- Left: request editor + add §§ ----
        val reqPanel = JPanel(BorderLayout())
        reqPanel.border = Theme.titled("Request (select a value, then \"Add §§\")")
        reqPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER)
        val reqSouth = JPanel(FlowLayout(FlowLayout.LEFT))
        reqSouth.add(addPosBtn)
        reqSouth.add(JButton("Clear positions").apply {
            addActionListener { positions.clear() }
        })
        reqPanel.add(reqSouth, BorderLayout.SOUTH)

        // ---- Right: tabbed (Positions / Payloads / Options) ----
        val rightTabs = JTabbedPane().apply {
            font = Theme.h2
            addTab("Positions", JScrollPane(positions))
            addTab("Payloads", JScrollPane(payloads))
            addTab("Options", JScrollPane(buildOptionsPanel()))
            addTab("Export", JScrollPane(ExportPanel { results.snapshot() }))
        }

        reqPanel.preferredSize = Dimension(650, 420)
        reqPanel.minimumSize = Dimension(300, 200)
        rightTabs.preferredSize = Dimension(560, 420)
        rightTabs.minimumSize = Dimension(360, 200)
        val configSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, rightTabs).apply {
            resizeWeight = 0.55
            dividerSize = 6
            addHierarchyListener { e ->
                if (e.changeFlags and java.awt.event.HierarchyEvent.SHOWING_CHANGED.toLong() != 0L && isShowing) {
                    SwingUtilities.invokeLater { setDividerLocation(0.55) }
                }
            }
        }

        // ---- Results ----
        val resultsScroll = JScrollPane(results.table)
        resultsScroll.border = Theme.titled("Live results (sort by Confidence to triage early)")

        val previewTabs = JTabbedPane().apply {
            addTab("Request", previewRequestEditor.uiComponent())
            addTab("Response", previewResponseEditor.uiComponent())
            font = Theme.h2
        }
        val previewPanel = JPanel(BorderLayout()).apply {
            border = Theme.titled("Selected row")
            add(previewTabs, BorderLayout.CENTER)
        }

        val resultsSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, resultsScroll, previewPanel).apply {
            resizeWeight = 0.55
            dividerSize = 6
        }

        val vertical = JSplitPane(JSplitPane.VERTICAL_SPLIT, configSplit, resultsSplit).apply {
            resizeWeight = 0.45
            dividerSize = 6
        }

        root.add(vertical, BorderLayout.CENTER)

        // ---- Footer ----
        val footer = JPanel(BorderLayout())
        footer.border = BorderFactory.createEmptyBorder(6, 2, 0, 2)
        val footerLeft = JPanel(FlowLayout(FlowLayout.LEFT))
        footerLeft.add(statusLabel)
        val footerRight = JPanel(FlowLayout(FlowLayout.RIGHT))
        footerRight.add(startBtn); footerRight.add(stopBtn)
        footer.add(footerLeft, BorderLayout.WEST)
        footer.add(footerRight, BorderLayout.EAST)
        root.add(footer, BorderLayout.SOUTH)

        wireEvents()
        return root
    }

    private fun buildOptionsPanel(): JPanel {
        val panel = JPanel(GridBagLayout())
        panel.border = Theme.titled("Attack options")
        val c = GridBagConstraints().apply {
            insets = Insets(4, 8, 4, 8); anchor = GridBagConstraints.WEST
        }

        c.gridx = 0; c.gridy = 0; panel.add(JLabel("Mode:"), c)
        c.gridx = 1; c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        panel.add(attackModeBox, c)
        c.weightx = 0.0; c.fill = GridBagConstraints.NONE

        c.gridx = 0; c.gridy = 1; panel.add(JLabel("Concurrency:"), c)
        c.gridx = 1; panel.add(concurrencySpinner, c)

        c.gridx = 0; c.gridy = 2; panel.add(JLabel("Delay (ms):"), c)
        c.gridx = 1; panel.add(delaySpinner, c)

        c.gridx = 0; c.gridy = 3; panel.add(JLabel("Max requests:"), c)
        c.gridx = 1; panel.add(maxRequestsSpinner, c)

        c.gridx = 0; c.gridy = 4; c.gridwidth = 2
        c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        panel.add(JSeparator(), c)
        c.weightx = 0.0; c.fill = GridBagConstraints.NONE

        c.gridy = 5; panel.add(pruneCheck, c)
        c.gridy = 6; panel.add(urlEncCheck, c)
        c.gridy = 7; panel.add(doubleUrlEncCheck, c)
        c.gridy = 8; panel.add(base64EncCheck, c)

        c.gridx = 0; c.gridy = 9; c.gridwidth = 2
        c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        panel.add(JSeparator(), c)
        c.weightx = 0.0; c.fill = GridBagConstraints.NONE

        c.gridy = 10
        c.gridwidth = 2
        c.fill = GridBagConstraints.BOTH
        c.weightx = 1.0; c.weighty = 1.0
        val hintText = """
            Modes
              • Sniper          — one § at a time, every payload against each position.
              • Battering-ram   — same payload into every position.
              • Pitchfork       — one wordlist per position, consumed in parallel.
              • Cluster-bomb    — cartesian product of all positions × wordlists.

            Concurrency : parallel in-flight requests. Keep low on fragile targets.
            Delay       : milliseconds before each request (rate-limit friendly).
            Max requests: hard cap; a confirmation pops up if the attack exceeds it.

            Tip: enable only the payload classes relevant to the position
            (e.g. SQLi + NoSQLi on a login field) to keep false positives down
            and scans fast.
        """.trimIndent()
        val hint = JTextArea(hintText).apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
            columns = 44
            rows = 14
            font = Font("Segoe UI", Font.PLAIN, 11)
            foreground = Theme.fgMuted
            background = panel.background
            border = BorderFactory.createEmptyBorder(6, 2, 2, 2)
        }
        panel.add(hint, c)
        return panel
    }

    private fun wireEvents() {
        addPosBtn.addActionListener { onAddPosition() }
        startBtn.addActionListener { onStart() }
        stopBtn.addActionListener { onStop() }
        results.table.selectionModel.addListSelectionListener { e ->
            if (e.valueIsAdjusting) return@addListSelectionListener
            val row = results.rowAtView(results.table.selectedRow) ?: return@addListSelectionListener
            previewRequestEditor.setRequest(row.request)
            row.response?.let { previewResponseEditor.setResponse(it) }
        }
    }

    fun loadRequest(req: HttpRequest) {
        currentBase = req
        requestEditor.setRequest(req)
        positions.clear()
        statusLabel.text = "Loaded request: ${req.method()} ${req.pathWithoutQuery()}"
    }

    private fun onAddPosition() {
        val base = currentBase ?: run {
            statusLabel.text = "Load a request first (right-click → Send to Injection Scanner)."
            return
        }
        val selection = requestEditor.selection().orElse(null) ?: run {
            statusLabel.text = "Select the value in the request first."
            return
        }
        val range = selection.offsets()
        val raw = base.toByteArray().bytes
        val start = range.startIndexInclusive()
        val end = range.endIndexExclusive()
        if (start >= end || end > raw.size) {
            statusLabel.text = "Invalid selection."
            return
        }
        val value = String(raw.copyOfRange(start, end), Charsets.ISO_8859_1)
        positions.add(InsertionPoint(start, end, value))
        statusLabel.text = "Added position [$start..$end] value=\"${value.take(30)}\""
    }

    private fun onStart() {
        val base = currentBase ?: run { statusLabel.text = "Load a request first."; return }
        val pos = positions.positions()
        if (pos.isEmpty()) { statusLabel.text = "Add at least one §§ insertion point."; return }
        val sets = payloads.selectedSets()
        if (sets.isEmpty()) { statusLabel.text = "Enable at least one payload class."; return }
        val mode = attackModeBox.selectedItem as AttackMode

        val sched = Scheduler(api, concurrencySpinner.value as Int, (delaySpinner.value as Int).toLong())
        val opts = ScanOptions(
            contextPrune = pruneCheck.isSelected,
            urlEncode = urlEncCheck.isSelected,
            doubleUrlEncode = doubleUrlEncCheck.isSelected,
            base64Encode = base64EncCheck.isSelected,
            collaboratorEnabled = payloads.collaboratorEnabled()
        )
        val collab = if (opts.collaboratorEnabled) {
            try { api.collaborator().createClient() } catch (t: Throwable) { null }
        } else null
        val runner = JobRunner(api, sched, opts, collab)
        val budget = runner.estimate(mode, pos, sets)
        val cap = maxRequestsSpinner.value as Int
        if (budget > cap) {
            val choice = JOptionPane.showConfirmDialog(
                component,
                "This attack will send ~$budget requests, over the configured cap of $cap.\n" +
                    "Continue anyway? (Consider narrowing positions, wordlists, or mode.)",
                "Request budget",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            )
            if (choice != JOptionPane.YES_OPTION) return
        } else {
            val ok = JOptionPane.showConfirmDialog(
                component,
                "Launch $budget requests against ${base.httpService().host()}?",
                "Confirm",
                JOptionPane.OK_CANCEL_OPTION
            )
            if (ok != JOptionPane.OK_OPTION) return
        }

        results.clear()
        scheduler = sched
        jobRunner = runner
        startBtn.isEnabled = false
        stopBtn.isEnabled = true
        statusLabel.text = "Sending baseline…"

        runner.sendBaseline(base) { baseline ->
            SwingUtilities.invokeLater { statusLabel.text = "Baseline OK — launching $budget requests…" }
            runner.run(base, pos, mode, sets, baseline) { row ->
                SwingUtilities.invokeLater { results.add(row) }
            }
            sched.sealAndWatch {
                SwingUtilities.invokeLater {
                    startBtn.isEnabled = true
                    stopBtn.isEnabled = false
                    val oobMsg = if (collab != null) {
                        try {
                            val n = collab.getAllInteractions().size
                            "  ·  Collaborator interactions: $n"
                        } catch (t: Throwable) { "" }
                    } else ""
                    statusLabel.text = "Scan complete — ${results.table.rowCount} results.$oobMsg"
                }
            }
        }
    }

    private fun onStop() {
        scheduler?.abort()
        startBtn.isEnabled = true
        stopBtn.isEnabled = false
        statusLabel.text = "Stopped."
    }
}
