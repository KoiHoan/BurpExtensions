package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class _3SocketHandler implements BurpExtension {
    MontoyaApi api;
    Logging logging;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging=api.logging();
        api.extension().setName("Sockethandler");
        this.logging.logToOutput("Socket Handler");
        api.websockets().registerWebSocketCreatedHandler(new _3CustomWebsocketCreatedHandler(api));

    }
}
