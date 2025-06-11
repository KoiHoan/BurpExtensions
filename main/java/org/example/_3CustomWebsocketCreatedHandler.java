package org.example;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.websocket.WebSocket;
import burp.api.montoya.websocket.WebSocketCreated;
import burp.api.montoya.websocket.WebSocketCreatedHandler;

public class _3CustomWebsocketCreatedHandler implements WebSocketCreatedHandler {
    MontoyaApi api;
    Logging logging;

    public _3CustomWebsocketCreatedHandler(MontoyaApi api) {
        this.api = api;
        this.logging=api.logging();
    }


    @Override
    public void handleWebSocketCreated(WebSocketCreated webSocketCreated){
        WebSocket webSocket = webSocketCreated.webSocket();
        webSocket.registerMessageHandler(new _3CustomWebsocketHandler(api));
        //
    }
}
