package org.example;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.utilities.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.util.HexFormat;

public class _4CustomHttpRequestEditorTab implements ExtensionProvidedHttpRequestEditor {
    static String keyHex = "eeb27c55483270a92682dab01b85fdea";
    static String ivHex = "ecbc1312cfdc2a0e1027b1eaf577dce8";
    HttpRequestResponse currentRequestResponse;
    MontoyaApi api;
    Logging logging;
    EditorCreationContext creationContext;
    RawEditor requestEditorTab;
    Base64Utils base64Utils;

    public _4CustomHttpRequestEditorTab(MontoyaApi api, EditorCreationContext creationContext) {
        this.api = api;
        this.creationContext = creationContext;
        this.logging=api.logging();
        this.base64Utils=api.utilities().base64Utils();

        if (creationContext.editorMode()==EditorMode.READ_ONLY){
            requestEditorTab = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        } else {
            requestEditorTab = api.userInterface().createRawEditor();
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse){
        return true;
    }

    @Override
    public String caption(){
        return "Decrypted";
    }

    @Override
    public Component uiComponent(){
        return requestEditorTab.uiComponent();
    }

    @Override
    public Selection selectedData(){
        if (requestEditorTab.selection().isPresent()){
            return requestEditorTab.selection().get();
        } else {
            return null;
        }
    }

    @Override
    public boolean isModified(){
        return requestEditorTab.isModified();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse){
        this.currentRequestResponse = requestResponse;
        HttpRequest request = requestResponse.request();
        ByteArray body = request.body();
        ByteArray decodedBody = this.base64Utils.decode(body);
        try {
            byte[] iv = HexFormat.of().parseHex(this.ivHex);
            byte[] secretKey = HexFormat.of().parseHex(this.keyHex);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE,secretKeySpec,ivParameterSpec );
            byte[] decryptedBody = aesCipher.doFinal(decodedBody.getBytes());
            this.requestEditorTab.setContents(ByteArray.byteArray(decryptedBody));
        } catch (Exception e){
            this.logging.logToError(e);
        }
    }

    @Override
    public HttpRequest getRequest(){
        if (isModified()){
            ByteArray newBody = requestEditorTab.getContents();
            try {
                byte[] iv = HexFormat.of().parseHex(this.ivHex);
                byte[] secretKey = HexFormat.of().parseHex(this.keyHex);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
                Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aesCipher.init(Cipher.ENCRYPT_MODE,secretKeySpec,ivParameterSpec );
                byte[] encryptedBody = aesCipher.doFinal(newBody.getBytes());
                ByteArray encodedBody = this.base64Utils.encode(ByteArray.byteArray(encryptedBody));
                HttpRequest oldRequest = this.currentRequestResponse.request();
                HttpRequest newRequest = oldRequest.withBody(encodedBody);
                return newRequest;

            }
            catch (Exception e){
                this.logging.logToError(e);
                return this.currentRequestResponse.request();
            }
        } else {
            return this.currentRequestResponse.request();
        }
    }



}
