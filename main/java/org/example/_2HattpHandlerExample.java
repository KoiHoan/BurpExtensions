package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class _2HattpHandlerExample implements BurpExtension {
    MontoyaApi api;
    Logging logging;
    @Override
    public void initialize(MontoyaApi api) {

        this.api = api;
        this.logging= api.logging();
        api.extension().setName("HttpHandlerExample");
        logging.logToOutput("HTTPhandlerexmaple");
        api.http().registerHttpHandler(new _2CustomHttpHandler(api));

    }

}
