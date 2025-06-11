package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class _4RequestResponseEditor implements BurpExtension {
    MontoyaApi api;
    Logging logging;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging=api.logging();
        api.extension().setName("RequestResponseEditor");
        this.logging.logToOutput("RequestResponseEditor");

        _4CustomHttpRequestResponseEditor customHttpRequestResponseEditor = new _4CustomHttpRequestResponseEditor(api);
        api.userInterface().registerHttpRequestEditorProvider(customHttpRequestResponseEditor);
        api.userInterface().registerHttpResponseEditorProvider(customHttpRequestResponseEditor);
    }
}
