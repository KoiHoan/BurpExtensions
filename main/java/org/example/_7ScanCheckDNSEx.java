package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class _7ScanCheckDNSEx implements BurpExtension {
    MontoyaApi api;
    Logging logging;


    public void initialize(MontoyaApi api){
        this.api = api;
        this.logging = api.logging();
        this.logging.logToOutput("Scan check DNS Collab example");
        this.api.extension().setName("ScanCheckCollabExample");
        this.api.scanner().registerScanCheck(new _7CustomScanCheck(api));
    }
}
