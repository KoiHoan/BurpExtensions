package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class _5ContextMenuExample implements BurpExtension {
    MontoyaApi api;
    Logging logging;

    @Override
    public void initialize(MontoyaApi api){
        this.api = api;
        this.logging = api.logging();
        api.extension().setName("ContextMenuExample");
        this.logging.logToOutput("ContextMenuExample2");
        api.userInterface().registerContextMenuItemsProvider(new _5CustomContextMenuItemsProvider(api));
    }
}
