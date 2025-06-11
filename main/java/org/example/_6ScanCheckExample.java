package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class _6ScanCheckExample implements BurpExtension {
    MontoyaApi api;
    Logging logging;

    public void initialize(MontoyaApi api){
        this.api = api;
        this.logging = api.logging();
        this.logging.logToOutput("Scan check example");
        this.api.extension().setName("ScanCheckExample");
        this.api.scanner().registerScanCheck(new _6CustomScanCheck(api));
    }
}
