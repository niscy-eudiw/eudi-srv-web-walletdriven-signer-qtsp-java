package eu.europa.ec.eudi.signer.r3.resource_server.exception;

import org.springframework.http.HttpStatusCode;

public class RestControllersException {

    private HttpStatusCode statusCode;
    private String error;
    private String errorDescription;

    public RestControllersException(HttpStatusCode statusCode, String error, String errorDescription) {
        this.statusCode = statusCode;
        this.error = error;
        this.errorDescription = errorDescription;
    }
}
