/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.common_tools.utils;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

public class WebUtils {

    public static class StatusAndMessage{
        private int statusCode;
        private String message;

        public StatusAndMessage(int statusCode) {
            this.statusCode = statusCode;
        }

        public StatusAndMessage(int statusCode, String message) {
            this.statusCode = statusCode;
            this.message = message;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public void setStatusCode(int statusCode) {
            this.statusCode = statusCode;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }

    public static String convertStreamToString(InputStream is) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line = reader.readLine();
        while (line != null) {
            sb.append(line);
            line = reader.readLine();
            if(line != null) sb.append("\n");
        }
        reader.close();
        is.close();
        return sb.toString();
    }

    public static String getSanitizedCookieString(String cookieSession){
        // Allow alphanumeric characters, spaces, `-`, `_`, `.`, `~`, `=`, `;`, and `,`
        // Remove disallowed characters and strip extra whitespace
		return cookieSession.replaceAll("[^a-zA-Z0-9 \\-_.=;,~]", "").replaceAll("[\\r\\n]", "").trim();
    }

    public static StatusAndMessage httpGetRequests(String url, Map<String, String> headers){
        try(CloseableHttpClient httpClient = HttpClients.createDefault() ) {
            HttpResponse response = httpGetRequestCommon(httpClient, url, headers);

            int statusCode = response.getStatusLine().getStatusCode();
            if(statusCode == 200){
                HttpEntity entity = response.getEntity();
                if (entity == null) throw new Exception("Presentation Response from Verifier is empty.");

                InputStream inStream = entity.getContent();
                String message = WebUtils.convertStreamToString(inStream);
                return new StatusAndMessage(statusCode, message);
            }
            else return new StatusAndMessage(statusCode, "Request failed with status code: " + statusCode);
        }
        catch (IOException e){
            return new StatusAndMessage(500, "Network error: Unable to connect to the server. Please try again.");
        }
        catch (Exception e) {
            return new StatusAndMessage(500, "An unexpected error occurred: " + e.getMessage());
        }
    }

    private static HttpResponse httpGetRequestCommon(HttpClient httpClient, String url,
                                                     Map<String, String> headers) throws Exception {
        HttpGet request = new HttpGet(url);

        // Set headers
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            request.setHeader(entry.getKey(), entry.getValue());
        }

        // Send Post Request
        return httpClient.execute(request);
    }

    public static HttpResponse httpGetRequestsWithCustomSSLContext(TrustManager[] tm, KeyManager[] keystore,
                                                                   String url, Map<String, String> headers) throws Exception {
        // Create SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keystore, tm, null);

        HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        return httpGetRequestCommon(httpClient, url, headers);
    }

    private static HttpResponse httpPostRequestCommon(HttpClient httpClient, String url,
                                                      Map<String, String> headers, String body) throws Exception {
        HttpPost request = new HttpPost(url);

        // Set headers
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            request.setHeader(entry.getKey(), entry.getValue());
        }

        // Set Message Body
        StringEntity requestEntity = new StringEntity(body);
        request.setEntity(requestEntity);

        // Send Post Request
        return httpClient.execute(request);
    }

    public static HttpResponse httpPostRequest(String url, Map<String, String> headers, String body) throws Exception {
        HttpClient httpClient = HttpClients.createDefault();
        return httpPostRequestCommon(httpClient, url, headers, body);
    }

    public static HttpResponse httpPostRequestsWithCustomSSLContext(TrustManager[] tm, KeyManager[] keystore,
                                                                    String url, String jsonBody,
                                                                    Map<String, String> headers) throws Exception {
        // Create SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keystore, tm, null);

        HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        return httpPostRequestCommon(httpClient, url, headers, jsonBody);
    }

}
