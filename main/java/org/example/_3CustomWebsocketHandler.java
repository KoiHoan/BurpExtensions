package org.example;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;
import burp.api.montoya.websocket.*;

import java.math.BigInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class _3CustomWebsocketHandler implements MessageHandler{
    MontoyaApi api;
    Logging logging;
    CryptoUtils cryptoUtils;

    public _3CustomWebsocketHandler(MontoyaApi api) {
        this.api = api;
        this.logging=api.logging();
        this.cryptoUtils=api.utilities().cryptoUtils();

    }

    public TextMessageAction handleTextMessage(TextMessage message){
        String payload = message.payload();
        Direction direction = message.direction();
//        if(direction== Direction.CLIENT_TO_SERVER){
//            logging.logToOutput("Client to server");
//        } else{
//            logging.logToOutput("Server to client");
//        }

        if (payload.contains("my_event") && direction==Direction.CLIENT_TO_SERVER){
            Pattern P = Pattern.compile(".*\"data\"\\:\"([^\"]+)\".*\"hash\"\\:\"([^\"]+)\"");
            Matcher M = P.matcher(payload);

            if (M.find() && M.groupCount()==2){
                ByteArray sha256hash = cryptoUtils.generateDigest(ByteArray.byteArray(M.group(1)), DigestAlgorithm.SHA_256);
                String digest = String.format("%064x", new BigInteger(1, sha256hash.getBytes()));
                String newMessage = payload.replace(M.group(2), digest);
                logging.logToOutput("Message with updated hash:");
                logging.logToOutput(newMessage);

                return TextMessageAction.continueWith(newMessage);
            } else {
                logging.logToOutput("Data and hash not found. Returning original message.");
                return TextMessageAction.continueWith(message);
            }

        }
        return TextMessageAction.continueWith(message);
    }

    public BinaryMessageAction handleBinaryMessage(BinaryMessage message){
        return BinaryMessageAction.continueWith(message);
    }
}
