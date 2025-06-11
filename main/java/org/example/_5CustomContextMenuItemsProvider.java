package org.example;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.utilities.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

public class _5CustomContextMenuItemsProvider implements ContextMenuItemsProvider {
    static String keyHex = "eeb27c55483270a92682dab01b85fdea";
    static String ivHex = "ecbc1312cfdc2a0e1027b1eaf577dce8";
    MontoyaApi api;
    Logging logging;
    Base64Utils base64Utils;


    public _5CustomContextMenuItemsProvider(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.base64Utils = api.utilities().base64Utils();

    }

    @Override
    public List<Component> provideMenuItems (ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<Component>();
        event.messageEditorRequestResponse().ifPresent(messageEditorReqRes -> {
            messageEditorReqRes.selectionOffsets().ifPresent(selectionOffset -> {
                HttpRequestResponse reqRes = messageEditorReqRes.requestResponse();
                MessageEditorHttpRequestResponse.SelectionContext selectionContext =
                        messageEditorReqRes.selectionContext();
                JMenuItem decryptItem = new JMenuItem("Decrypt");
                JMenuItem encryptItem = new JMenuItem("Encrypt");
                decryptItem.addActionListener(al -> {
                    ByteArray reqResBytes;
                    if (selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST){
                        reqResBytes = reqRes.request().toByteArray();
                    } else {
                        reqResBytes = reqRes.response().toByteArray();
                    }
                    ByteArray selectedBytes = reqResBytes.subArray(selectionOffset.startIndexInclusive(),
                            selectionOffset.endIndexExclusive());
                    ByteArray decodedSelectedBytes = this.base64Utils.decode(selectedBytes);
                    byte[] decryptedMessage = encryptDecrypt(Cipher.DECRYPT_MODE, decodedSelectedBytes.getBytes(),
                            this.logging);
                    String decryptedMessageString = new String(decryptedMessage);
                    ByteArray editedMessageBytes = reqResBytes.subArray(0, selectionOffset.startIndexInclusive());
                    editedMessageBytes=editedMessageBytes.withAppended(ByteArray.byteArray(decryptedMessage));
                    if (selectionOffset.endIndexExclusive()<reqResBytes.length()){
                        editedMessageBytes.withAppended(reqResBytes.subArray(selectionOffset.endIndexExclusive(),
                                reqResBytes.length()));

                    }
                    try {
                        if (selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST){
                            messageEditorReqRes.setRequest(HttpRequest.httpRequest(editedMessageBytes));
                        } else {
                            messageEditorReqRes.setResponse(HttpResponse.httpResponse(editedMessageBytes));
                        }
                    } catch (UnsupportedOperationException ex) {
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                JTextArea textArea = new JTextArea(20,60);
                                textArea.setLineWrap(true);
                                textArea.setText(decryptedMessageString);
                                JOptionPane.showMessageDialog(null, new JScrollPane(textArea),
                                        "Edited Message", JOptionPane.INFORMATION_MESSAGE);

                            }
                        });
                    }

                });
                encryptItem.addActionListener(al -> {
                    ByteArray reqResBytes;
                    if (selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST){
                        reqResBytes = reqRes.request().toByteArray();
                    } else {
                        reqResBytes = reqRes.response().toByteArray();
                    }
                    ByteArray selectedBytes = reqResBytes.subArray(selectionOffset.startIndexInclusive(),
                            selectionOffset.endIndexExclusive());

                    byte[] encryptedMessage = encryptDecrypt(Cipher.ENCRYPT_MODE, selectedBytes.getBytes(),
                            this.logging);
                    byte[] encodedMessage = this.base64Utils.encode(ByteArray.byteArray(encryptedMessage)).getBytes();
                    String encodedMessageString = new String(encodedMessage);
                    ByteArray editedMessageBytes = reqResBytes.subArray(0, selectionOffset.startIndexInclusive());
                    editedMessageBytes=editedMessageBytes.withAppended(ByteArray.byteArray(encodedMessage));
                    if (selectionOffset.endIndexExclusive()<reqResBytes.length()){
                        editedMessageBytes.withAppended(reqResBytes.subArray(selectionOffset.endIndexExclusive(),
                                reqResBytes.length()));

                    }
                    try {
                        if (selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST){
                            messageEditorReqRes.setRequest(HttpRequest.httpRequest(editedMessageBytes));
                        } else {
                            messageEditorReqRes.setResponse(HttpResponse.httpResponse(editedMessageBytes));
                        }
                    } catch (UnsupportedOperationException ex) {
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                JTextArea textArea = new JTextArea(20,60);
                                textArea.setLineWrap(true);
                                textArea.setText(encodedMessageString);
                                JOptionPane.showMessageDialog(null, new JScrollPane(textArea),
                                        "Edited Message", JOptionPane.INFORMATION_MESSAGE);

                            }
                        });
                    }

                });

                menuItems.add(decryptItem);
                menuItems.add(encryptItem);
            });

        });
        return menuItems;
    }

    public static byte[] encryptDecrypt (int encryptOrDecrypt, byte[]data, Logging logging) {
        try {
            byte[] iv = HexFormat.of().parseHex(ivHex);
            byte[] secretKey = HexFormat.of().parseHex(keyHex);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(encryptOrDecrypt,secretKeySpec,ivParameterSpec );
            byte[]  processedData = aesCipher.doFinal(data);
            return processedData;
        } catch (Exception e) {
            logging.logToError(e.toString());
            return null;
        }
    }
}
