package eu.europa.ec.eudi.signer.r3.resource_server.config;

import eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsListResponse;
import io.swagger.v3.core.converter.ModelConverters;
import io.swagger.v3.core.converter.ResolvedSchema;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import java.util.List;
import java.util.function.Consumer;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI documentation of the CSC API v2 endpoints exposed by the Resource
 * Server.
 * <p>
 * The endpoints are discovered by springdoc from the controllers. This
 * configuration completes them with what cannot be inferred from the code: the
 * OAuth2 scope required by each endpoint (see WebSecurity), the actual response
 * status codes and the format of the error responses (see
 * GlobalExceptionHandler).
 */
@Configuration
public class SwaggerConfig {

    private static final String JSON = org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

    private static final String INFO_TAG = "Info";
    private static final String CREDENTIALS_TAG = "Credentials";
    private static final String SIGNATURES_TAG = "Signatures";

    private static final String OAUTH2 = "oauth2";
    private static final String BEARER_AUTH = "bearerAuth";

    private static final String SCOPE_SERVICE = "service";
    private static final String SCOPE_CREDENTIAL = "credential";
    private static final String SCOPE_CREDENTIAL_CREATION = "credential-creation";
    private static final String SCOPE_CREDENTIAL_DELETION = "credential-deletion";

    private static final String SCHEMA_ERROR = "ErrorResponse";

    @Bean
    GroupedOpenApi publicApi() {
        return GroupedOpenApi.builder()
                .group("public-apis")
                .pathsToMatch("/csc/v2/**")
                .addOpenApiCustomizer(cscEndpoints())
                .build();
    }

    @Bean
    OpenAPI customOpenAPI(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String authorizationServerUrl,
                          @Value("${RESOURCE_SERVER}") String resourceServerUrl) {
        return new OpenAPI()
                .servers(List.of(new Server().url(resourceServerUrl)))
                .info(new Info()
                        .title("EUDI Wallet-Driven Signer QTSP - Resource Server")
                        .description("""
						  Remote Signing Service Provider implementing the Cloud Signature Consortium (CSC) API v2.2.0.0 \
						  for credential management and remote signing of hashes.0""")
                        .version("2.2.0.0"))
                .tags(List.of(
                        new Tag().name(INFO_TAG).description("Information about the remote service (CSC API, section 11.1)"),
                        new Tag().name(CREDENTIALS_TAG).description("Management of the user's credentials: key pair and "
                                + "X.509 certificate (CSC API, sections 11.4 to 11.7)"),
                        new Tag().name(SIGNATURES_TAG).description("Remote signature of hashes (CSC API, section 11.13)")))
                .components(new Components()
                        .addSecuritySchemes(OAUTH2, new SecurityScheme()
                                .type(SecurityScheme.Type.OAUTH2)
                                .description("""
								OAuth 2.0 Authorization Code flow with PKCE (CSC API, section 8.2). The scopes are:
								* `service`: service authorization to access the CSC API.
								* `credential`: credential authorization to sign. Also grants service authorization for \
								`credentials/info` and `signatures/signHash`.
								* `credential-creation`: credential creation authorization. Also grants service \
								authorization for `credentials/create`.
								* `credential-deletion`: credential deletion authorization. Also grants service \
								authorization for `credentials/delete`.

								The `credential`, `credential-creation` and `credential-deletion` requests also need \
								`authorization_details` (or the CSC request parameters), which the Swagger UI authorization \
								dialog does not support: obtain the token from the Authorization Server and use `bearerAuth` \
								instead.""")
                                .flows(new OAuthFlows().authorizationCode(new OAuthFlow()
                                        .authorizationUrl(authorizationServerUrl + "/oauth2/authorize")
                                        .tokenUrl(authorizationServerUrl + "/oauth2/token")
                                        .scopes(new Scopes()
                                                .addString(SCOPE_SERVICE, "Service authorization to access the CSC API")
                                                .addString(SCOPE_CREDENTIAL, "Credential authorization to sign the authorized hashes "
                                                        + "with the authorized credential")
                                                .addString(SCOPE_CREDENTIAL_CREATION, "Credential creation authorization")
                                                .addString(SCOPE_CREDENTIAL_DELETION, "Credential deletion authorization for the "
                                                        + "authorized credential")))))
                        .addSecuritySchemes(BEARER_AUTH, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("Access token issued by the Authorization Server (RFC 6750)"))
                        .addSchemas(SCHEMA_ERROR, errorSchema()));
    }

    private OpenApiCustomizer cscEndpoints() {
        return openApi -> {
            ResolvedSchema credentialInfo = ModelConverters.getInstance().readAllAsResolvedSchema(CredentialsListResponse.CredentialInfo.class);
            credentialInfo.referencedSchemas.forEach(openApi.getComponents()::addSchemas);
            String credentialInfoSchema = credentialInfo.schema.getName();

            document(openApi, "/csc/v2/info", operation -> operation
                    .operationId("info")
                    .tags(List.of(INFO_TAG))
                    .summary("Get information about the remote service (CSC API, section 11.1)")
                    .description("""
						Returns information about the remote service and the list of the API methods it supports.

						Mandatory for every remote service. Does not require authentication.""")
                    .security(List.of())
                    .responses(new ApiResponses().addApiResponse("200", ok(operation,
                            "Information about the remote service."))));

            document(openApi, "/csc/v2/credentials/list", operation -> operation
                    .operationId("credentialsList")
                    .tags(List.of(CREDENTIALS_TAG))
                    .summary("List the credentials of the user (CSC API, section 11.6)")
                    .description("""
						Returns the list of credentials of the user. If requested with \
						`credentialInfo=true`, it also returns the information about each credential.

						Service authorization is user-specific: the user is identified by the access token, so `userID` \
						must not be sent. If the user has no active credential, a new one is created first.""")
                    .security(scopes(SCOPE_SERVICE, SCOPE_CREDENTIAL, SCOPE_CREDENTIAL_CREATION, SCOPE_CREDENTIAL_DELETION))
                    .responses(errorResponses(
                            "Malformed authorization header.",
                            "`userID` present: service authorization is user-specific.",
                            "Invalid `certificates` parameter.")
                            .addApiResponse("200", ok(operation, "Credentials of the user."))));

            document(openApi, "/csc/v2/credentials/info", operation -> operation
                    .operationId("credentialsInfo")
                    .tags(List.of(CREDENTIALS_TAG))
                    .summary("Get information about a credential (CSC API, section 11.7)")
                    .description("""
                        Retrieves the credential. If requested, it can also return the signing certificate, the whole associated certificatechain, additional information about the signing certificate and/or information about the authorizationmechanism required to authorize the access to the credential for remote signing""")
                    .security(scopes(SCOPE_SERVICE, SCOPE_CREDENTIAL, SCOPE_CREDENTIAL_CREATION, SCOPE_CREDENTIAL_DELETION))
                    .responses(errorResponses(
                            "Malformed authorization header.",
                            "Missing (or invalid type) string parameter `credentialID`.",
                            "Invalid parameter `credentialID`.",
                            "Invalid parameter `certificates`.")
                            .addApiResponse("200", ok(operation, "Information about the credential."))));

            document(openApi, "/csc/v2/credentials/create", operation -> operation
                    .operationId("credentialsCreate")
                    .tags(List.of(CREDENTIALS_TAG))
                    .summary("Create a credential (CSC API, section 11.4)")
                    .description("""
						Creates a new signing credential: an ECDSA P-256 key pair and its certificate, issued in accordance \
						with `credentialCreationRequest.certificatePolicy`. Requires credential creation authorization.

						The certificate subject is taken from `credentialCreationRequest.subjectData` or, if absent, from \
						the identity claims of the access token.
                                                
						If `credentialInfo` is `true`, the response contains the information about the new credential, \
						completed according to `certificates` and `certInfo`.""")
                    .security(scopes(SCOPE_CREDENTIAL_CREATION))
                    .responses(errorResponses(
                            "Malformed authorization header.",
                            "Missing (or invalid type) parameter `credentialCreationRequest`.",
                            "Missing (or invalid type) string parameter `certificatePolicy`.",
                            "Invalid parameter `certificatePolicy`.",
                            "Invalid parameter `subjectData`.",
                            "Invalid parameter `certificates`, `certInfo` or `authData`.")
                            .addApiResponse("201", new ApiResponse()
                                    .description("Credential created. The body contains the credential information only if "
                                            + "`credentialInfo` is `true`.")
                                    .content(jsonContent(new Schema<>().$ref("#/components/schemas/" + credentialInfoSchema))))));

            document(openApi, "/csc/v2/credentials/delete", operation -> operation
                    .operationId("credentialsDelete")
                    .tags(List.of(CREDENTIALS_TAG))
                    .summary("Delete a credential (CSC API, section 11.5)")
                    .description("""
						Deletes a credential of the user, identified by `credentialDeletionRequest.credentialID`. Requires \
						credential deletion authorization: the `credentialID` must be the one authorized in the access \
						token.""")
                    .security(scopes(SCOPE_CREDENTIAL_DELETION))
                    .responses(errorResponses(
                            "Malformed authorization header.",
                            "Missing (or invalid type) string parameter `credentialID`.",
                            "Invalid parameter `credentialID`.",
                            "Contradicting `credentialID` parameters: the request and the authorization details disagree.")
                            .addApiResponse("204", new ApiResponse().description("Credential deleted."))));

            document(openApi, "/csc/v2/signatures/signHash", operation -> operation
                    .operationId("signaturesSignHash")
                    .tags(List.of(SIGNATURES_TAG))
                    .summary("Sign hashes (CSC API, section 11.13)")
                    .description("""
						Calculates the raw digital signature of one or more hashes with a credential of the user. Requires \
						credential authorization, given by an access token with `credential` scope in the \
						`Authorization` header.

						The `credentialID`, `hashes` and `hashAlgorithmOID` must match the ones authorized in the access \
						token, and the number of hashes cannot exceed the authorized `numSignatures`. The `hashAlgorithmOID` \
						must be SHA-256 or stronger, and is ignored if implied by `signAlgo` or `signAlgoParams`.""")
                    .security(scopes(SCOPE_CREDENTIAL))
                    .responses(errorResponses(
                            "Malformed authorization header.",
                            "Missing (or invalid type) string parameter `credentialID`, or invalid `credentialID`.",
                            "Missing (or invalid type) array parameter `hashes`, empty `hashes` array, invalid Base64 "
                            + "hash or invalid digest value length.",
                            "Hash not authorized by the access token with `credential` scope.",
                            "Missing (or invalid type) string parameter `signAlgo`, or invalid `signAlgo` or "
                            + "`signAlgoParams`.",
                            "Missing `hashAlgorithmOID` when not implied by `signAlgo`, invalid `hashAlgorithmOID`, or "
                            + "`hashAlgorithmOID` contradicting `signAlgo` or `signAlgoParams`.",
                            "Invalid parameter `operationMode` or `clientData`.",
                            "Expired signing certificate.")
                            .addApiResponse("200", ok(operation,
                                    "Base64-encoded signature values (`signatures`), in the same order as the hashes in "
                                    + "the request."))));
        };
    }

    private static void document(OpenAPI openApi, String path, Consumer<Operation> customizer) {
        PathItem pathItem = openApi.getPaths() == null ? null : openApi.getPaths().get(path);
        if (pathItem != null && pathItem.getPost() != null) {
            customizer.accept(pathItem.getPost());
        }
    }

    private static ApiResponse ok(Operation operation, String description) {
        ApiResponse response = operation.getResponses() == null ? null : operation.getResponses().get("200");
        return (response == null ? new ApiResponse() : response).description(description);
    }

    private static List<SecurityRequirement> scopes(String... scopes) {
        return List.of(
                new SecurityRequirement().addList(OAUTH2, List.of(scopes)),
                new SecurityRequirement().addList(BEARER_AUTH));
    }

    private static ApiResponses errorResponses(String... badRequestCases) {
        StringBuilder description = new StringBuilder("`invalid_request`: the request is missing a required parameter, "
                + "includes an invalid parameter value or is not authorized by the access token. In particular:");
        for (String badRequestCase : badRequestCases) {
            description.append("\n* ").append(badRequestCase);
        }

        ApiResponse badRequest = new ApiResponse()
                .description(description.toString())
                .content(jsonContent(new Schema<>().$ref("#/components/schemas/" + SCHEMA_ERROR)));
        return new ApiResponses()
                .addApiResponse("400", badRequest)
                .addApiResponse("401", new ApiResponse().description("`invalid_token` or `expired_token`: missing, invalid, "
                        + "expired or revoked access token."))
                .addApiResponse("403", new ApiResponse().description("The access token does not have the required scope."))
                .addApiResponse("500", new ApiResponse().description("The server encountered an unexpected condition."));
    }

    private static Schema<?> errorSchema() {
        Schema<?> schema = new ObjectSchema()
                .description("Error message in `message`. For request validation errors, the object maps each invalid "
                        + "parameter to its error message instead.")
                .addProperty("message", new StringSchema().example("invalid_request: Invalid parameter credentialID."));
        schema.setAdditionalProperties(new StringSchema());
        return schema;
    }

    private static Content jsonContent(Schema<?> schema) {
        return new Content().addMediaType(JSON, new MediaType().schema(schema));
    }
}
