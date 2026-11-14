package com.burpinj

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.burpinj.ui.MainTab
import com.burpinj.ui.ContextMenu

class InjectionScannerExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Injection Scanner")
        val tab = MainTab(api)
        api.userInterface().registerSuiteTab("Injection Scanner", tab.component)
        api.userInterface().registerContextMenuItemsProvider(ContextMenu(tab))
        api.logging().logToOutput("Injection Scanner loaded.")
    }
}
