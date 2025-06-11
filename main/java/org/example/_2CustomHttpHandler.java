package org.example;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;

import java.math.BigInteger;

public class _2CustomHttpHandler implements HttpHandler {
    MontoyaApi api;
    Logging logging;
    CryptoUtils cryptoUtils;

    public _2CustomHttpHandler(MontoyaApi api) {
        this.api = api;
        this.logging=api.logging();
        this.cryptoUtils = api.utilities().cryptoUtils();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        try {
            boolean hasHashHeader = httpRequestToBeSent.hasHeader("Hash");
//            if (httpRequestToBeSent.toolSource().isFromTool(ToolType.INTRUDER, ToolType.PROXY, ToolType.REPEATER)){
//                return RequestToBeSentAction.continueWith(httpRequestToBeSent);
//            }

            if (hasHashHeader) {
                //            logging.logToOutput("Hash Header");
                ByteArray body = httpRequestToBeSent.body();
                ByteArray hashValue = cryptoUtils.generateDigest(body, DigestAlgorithm.SHA_256);
                //convert hex
                String digest = String.format("%064x", new BigInteger(1, hashValue.getBytes()));
                //            logging.logToOutput(digest);
                HttpRequest modifiedRequest = httpRequestToBeSent.withUpdatedHeader("Hash", digest);

                return RequestToBeSentAction.continueWith(modifiedRequest);


            }
            //        logging.logToOutput("Ko co hash");
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        } catch (Exception e) {
            logging.logToError("Error processing HTTP request: " + e.getMessage());
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }
}
