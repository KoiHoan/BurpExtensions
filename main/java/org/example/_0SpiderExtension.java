package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class _0SpiderExtension implements BurpExtension {
    MontoyaApi api;
    Logging logging;


    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        api.extension().setName("SpiderExtension");
        logging.logToOutput("Spider Extension Loaded");
        api.userInterface().registerContextMenuItemsProvider(new _0CustomContextMenuItemsProvider(api));

    }
}

