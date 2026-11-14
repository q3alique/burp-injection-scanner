package com.burpinj.ui

import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import javax.swing.JMenuItem

class ContextMenu(private val tab: MainTab) : ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        val req = event.messageEditorRequestResponse().map { it.requestResponse().request() }.orElse(null)
            ?: event.selectedRequestResponses().firstOrNull()?.request()
            ?: return emptyList()
        val item = JMenuItem("Send to Injection Scanner").apply {
            addActionListener { tab.loadRequest(req) }
        }
        return listOf(item)
    }
}
