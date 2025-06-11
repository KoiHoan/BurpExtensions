package org.example;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.*;

public class _4CustomHttpRequestResponseEditor implements HttpRequestEditorProvider, HttpResponseEditorProvider {
    MontoyaApi api;
    public _4CustomHttpRequestResponseEditor(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext){
        return new _4CustomHttpRequestEditorTab(api,creationContext);
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext){
        return new _4CustomHttpResponseEditorTab(api,creationContext);
    }
}

