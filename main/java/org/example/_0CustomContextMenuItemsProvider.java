package org.example;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class _0CustomContextMenuItemsProvider implements ContextMenuItemsProvider {
    MontoyaApi api;
    Logging logging;
    ExecutorService executorService;
    HttpRequest baseRequest;
    URI BaseURI;
    private final Set<String> targetLinks = new HashSet<>();
    private final Pattern LINK_PATTERN = Pattern.compile("href=\"(.*?)\"");

    public _0CustomContextMenuItemsProvider(MontoyaApi api){
        this.api = api;
        this.logging = api.logging();
        this.executorService = Executors.newFixedThreadPool(5);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<Component>();
        event.messageEditorRequestResponse().ifPresent(messageEditorReqRes -> {
            HttpRequestResponse reqRes = messageEditorReqRes.requestResponse();
            MessageEditorHttpRequestResponse.SelectionContext selectionContext =
                    messageEditorReqRes.selectionContext();

            HttpResponse res;
            if (selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST){
                this.baseRequest=reqRes.request();
                try {
                    this.BaseURI=new URI(this.baseRequest.url());
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }

            }
            JMenuItem menuItem = new JMenuItem("Spider");
            menuItem.addActionListener(e -> {
                executorService.submit(() -> {
                    crawl(this.BaseURI,this.baseRequest.path());

                });
            });
            menuItems.add(menuItem);
        });
        return menuItems;
    }


    public void sendRes(MontoyaApi api, HttpRequest req){
        api.http().sendRequest(req);
    }
    public HttpRequestResponse checkRequest(String path){
        try{
            HttpRequest newReq = this.baseRequest.withPath(path);
            return api.http().sendRequest(newReq);
        }
        catch (Exception e) {
            api.logging().logToError("Error requesting path: " + path + " - " + e.getMessage());
            return null;
        }
    }

    public List<String> extractPathsFrom(URI tempBaseURI, String path){
        URI newBaseURI = tempBaseURI.resolve(path);
        String newPath = newBaseURI.toString().replace(this.BaseURI.toString(),"/");
        List<String> links = new ArrayList<>();
        HttpRequestResponse response = checkRequest(newPath);
        if (response != null && response.response() != null) {
            String responseBody = response.response().bodyToString();
            Matcher matcher = LINK_PATTERN.matcher(responseBody);
            if (response != null && response.response() != null) {
                api.siteMap().add(response);
            }
            while (matcher.find()) {
                String matched = matcher.group(1);
                if (!matched.contains("http")) {
                    links.add(matcher.group(1));
                } else {
                    if (matched.contains(this.baseRequest.url())) {
                        links.add(matcher.group(1));
                    }
                }


            }
        }

        return links;
    }

    public void crawl(URI tempBaseURI, String path){
        URI newBaseURI = tempBaseURI.resolve(path);
        String newPath = newBaseURI.toString().replace(this.BaseURI.toString(),"/");
        List<String> paths = extractPathsFrom( newBaseURI,newPath);
        this.logging.logToOutput("Crawl from "+ newBaseURI.toString());
        for (String eachPath: paths){
            try{
                if (eachPath.contains("#")){
                    eachPath = eachPath.split("#")[0];
                }
                synchronized (this.targetLinks){
                    if (!this.targetLinks.contains(eachPath)){
                        this.targetLinks.add(eachPath);
                        this.logging.logToOutput("Found "+eachPath+" from "+newBaseURI.toString());

                        String finalEachPath = eachPath;
                        executorService.submit(() -> {crawl(newBaseURI,finalEachPath);});
                    }
                }
            } catch (Exception e){
                api.logging().logToError("Error processing path: " + eachPath + " - " + e.getMessage());
            }
        }
    }
}
