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
package eu.europa.ec.eudi.signer.r3.authorization_server.config;

import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2AuthorizationDetailsNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2CustomParameterNames;
import eu.europa.ec.eudi.signer.r3.authorization_server.web.security.oauth2.constants.OAuth2ScopesNames;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.QueryParameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import java.util.ArrayList;
import java.util.List;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * OpenAPI documentation of the OAuth2 endpoints exposed by the Authorization Server.
 * <p>
 * The OAuth2 endpoints are implemented as Spring Authorization Server filters, not as controllers,
 * so springdoc cannot discover them. Their paths, parameters and responses are therefore described
 * explicitly here, following the custom request converters (AuthorizationCodeRequestConverter and
 * TokenRequestConverter).
 */
@Configuration
public class SwaggerConfig {

    private static final String OAUTH2_TAG = "OAuth2";
    private static final String DISCOVERY_TAG = "Discovery";

    private static final String FORM_URLENCODED = org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
    private static final String JSON = org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

    private static final String CLIENT_SECRET_BASIC = "client_secret_basic";

    private static final String SCHEMA_AUTHORIZATION_DETAILS = "AuthorizationDetails";
    private static final String SCHEMA_TOKEN_RESPONSE = "TokenResponse";
    private static final String SCHEMA_OAUTH2_ERROR = "OAuth2Error";

    @Bean
    GroupedOpenApi publicApi(AuthorizationServerSettings authorizationServerSettings) {
        return GroupedOpenApi.builder()
                .group("public-apis")
                .pathsToMatch("/**")
                .addOpenApiCustomizer(oauth2Endpoints(authorizationServerSettings))
                .build();
    }

    @Bean
    OpenAPI customOpenAPI(ServiceURLConfig serviceURLConfig) {
        return new OpenAPI()
                .info(new Info()
                        .title("EUDI Wallet-Driven Signer QTSP - Authorization Server")
                        .description("OAuth 2.0 Authorization Server issuing the access tokens used to call the "
                                + "Resource Server (CSC API v2). Users are authenticated with OpenID4VP or a login form.")
                        .version("v1"))
                .servers(List.of(new Server().url(serviceURLConfig.getOauth2IssuerURL())))
                .tags(List.of(
                        new Tag().name(OAUTH2_TAG).description("Authorization Code flow with PKCE"),
                        new Tag().name(DISCOVERY_TAG).description("Authorization Server metadata and keys")))
                .components(new Components()
                        .addSecuritySchemes(CLIENT_SECRET_BASIC, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("basic")
                                .description("Client authentication with client_id and client_secret"))
                        .addSchemas(SCHEMA_AUTHORIZATION_DETAILS, authorizationDetailsSchema())
                        .addSchemas(SCHEMA_TOKEN_RESPONSE, tokenResponseSchema())
                        .addSchemas(SCHEMA_OAUTH2_ERROR, oauth2ErrorSchema()));
    }

    private OpenApiCustomizer oauth2Endpoints(AuthorizationServerSettings settings) {
        return openApi -> openApi
                .path(settings.getAuthorizationEndpoint(), new PathItem().get(authorizeOperation()))
                .path(settings.getTokenEndpoint(), new PathItem().post(tokenOperation()))
                .path(settings.getJwkSetEndpoint(), new PathItem().get(jwksOperation()));
    }

    // ---------------------------------------------------------------------------------------------
    // GET /oauth2/authorize
    // ---------------------------------------------------------------------------------------------

    private Operation authorizeOperation() {
        Operation operation = new Operation()
                .operationId("authorize")
                .addTagsItem(OAUTH2_TAG)
                .summary("Authorization request")
                .description("""
                        Starts the Authorization Code flow with PKCE. If the user is not authenticated, they are redirected \
                        to the authentication method configured for the client (OpenID4VP same-device, OpenID4VP cross-device \
                        or login form). After authentication, the user is redirected to `redirect_uri` with the `code` and `state`.

                        The requested authorization is defined by **either** `scope` **or** `authorization_details`:
                        * `scope=service` (default when neither is present): access to the credentials management APIs.
                        * `scope=credential` with `credentialID` or `signatureQualifier`, `numSignatures`, `hashes` and `hashAlgorithmOID`: \
                        authorization to sign the given hashes.
                        * `authorization_details` (RFC 9396), with `type` `credential`, `credential_creation` or `credential_deletion`. \
                        When present, `scope` is derived from the type and `lang` is ignored.""");

        operation.addParametersItem(queryParameter(OAuth2ParameterNames.RESPONSE_TYPE, true,
                "Must be `code`.", new StringSchema()._enum(List.of("code"))));
        operation.addParametersItem(queryParameter(OAuth2ParameterNames.CLIENT_ID, true,
                "Identifier of the registered client.", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2ParameterNames.REDIRECT_URI, false,
                "One of the redirect URIs registered for the client.", new StringSchema().format("uri")));
        operation.addParametersItem(queryParameter(OAuth2ParameterNames.SCOPE, false,
                "Requested scope. Ignored if `authorization_details` is present.",
                new StringSchema()._enum(List.of(OAuth2ScopesNames.SERVICE, OAuth2ScopesNames.CREDENTIAL))));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS, false,
                "JSON array (RFC 9396) with a single `AuthorizationDetails` object, URL encoded.", new StringSchema())
                .example("[{\"type\":\"credential\",\"credentialID\":\"<credential-id>\",\"numSignatures\":\"1\","
                        + "\"hashAlgorithmOID\":\"2.16.840.1.101.3.4.2.1\","
                        + "\"documentDigests\":[{\"hash\":\"<base64-hash>\",\"label\":\"document.pdf\"}]}]"));
        operation.addParametersItem(queryParameter(PkceParameterNames.CODE_CHALLENGE, true,
                "PKCE code challenge (RFC 7636).", new StringSchema()));
        operation.addParametersItem(queryParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, false,
                "PKCE code challenge method.", new StringSchema()._enum(List.of("S256", "plain"))._default("plain")));
        operation.addParametersItem(queryParameter(OAuth2ParameterNames.STATE, false,
                "Opaque value returned unchanged in the redirect to the client.", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.LANG, false,
                "Preferred language of the response. Ignored if `authorization_details` is present.", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.CREDENTIAL_ID, false,
                "Credential to authorize (`scope=credential`). Required if `signatureQualifier` is absent.", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.SIGNATURE_QUALIFIER, false,
                "Signature qualifier (`scope=credential`). Required if `credentialID` is absent.", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.NUM_SIGNATURES, false,
                "Number of signatures to authorize (required with `scope=credential`).", new IntegerSchema().minimum(java.math.BigDecimal.ONE)));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.HASHES, false,
                "Comma-separated list of base64url-encoded hashes to sign (required with `scope=credential`).", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.HASH_ALGORITHM_OID, false,
                "OID of the algorithm used to compute the hashes (required with `scope=credential`).", new StringSchema())
                .example("2.16.840.1.101.3.4.2.1"));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.DESCRIPTION, false,
                "Free-text description of the authorization request.", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.ACCOUNT_TOKEN, false,
                "Account token identifying the user account.", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.CLIENT_DATA, false,
                "Arbitrary data from the client.", new StringSchema()));

        return operation.responses(new ApiResponses()
                .addApiResponse("302", new ApiResponse()
                        .description("Redirect to the authentication page (user not authenticated), or to `redirect_uri` "
                                + "with `code` and `state` (user authenticated).")
                        .addHeaderObject("Location", new Header()
                                .description("`{redirect_uri}?code={authorization_code}&state={state}`")
                                .schema(new StringSchema().format("uri"))))
                .addApiResponse("400", errorResponse(
                        "`invalid_request` (missing or invalid parameter) or `unsupported_response_type`.")));
    }

    // ---------------------------------------------------------------------------------------------
    // POST /oauth2/token
    // ---------------------------------------------------------------------------------------------

    private Operation tokenOperation() {
        Schema<?> form = new ObjectSchema()
                .addProperty(OAuth2ParameterNames.GRANT_TYPE, new StringSchema()
                        ._enum(List.of("authorization_code")).description("Must be `authorization_code`."))
                .addProperty(OAuth2ParameterNames.CODE, new StringSchema()
                        .description("Authorization code received from the authorization endpoint."))
                .addProperty(OAuth2ParameterNames.CLIENT_ID, new StringSchema()
                        .description("Identifier of the client."))
                .addProperty(OAuth2ParameterNames.REDIRECT_URI, new StringSchema().format("uri")
                        .description("Must match the `redirect_uri` of the authorization request, if one was sent."))
                .addProperty(PkceParameterNames.CODE_VERIFIER, new StringSchema()
                        .description("PKCE code verifier (RFC 7636)."))
                .addProperty(OAuth2ParameterNames.CLIENT_SECRET, new StringSchema()
                        .description("Client secret, if the client authenticates with `client_secret_post`."))
                .addProperty(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, new StringSchema()
                        ._enum(List.of("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
                        .description("Client assertion type, if the client authenticates with a JWT."))
                .addProperty(OAuth2ParameterNames.CLIENT_ASSERTION, new StringSchema()
                        .description("Client assertion JWT, if the client authenticates with a JWT."))
                .addProperty(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS, new StringSchema()
                        .description("JSON array (RFC 9396), for authorization requests that used `authorization_details`."))
                .addProperty(OAuth2CustomParameterNames.CLIENT_DATA, new StringSchema()
                        .description("Arbitrary data from the client."));
        form.setRequired(List.of(OAuth2ParameterNames.GRANT_TYPE, OAuth2ParameterNames.CODE, OAuth2ParameterNames.CLIENT_ID));

        return new Operation()
                .operationId("token")
                .addTagsItem(OAUTH2_TAG)
                .summary("Access token request")
                .description("""
                        Exchanges an authorization code for an access token (JWT). The client authenticates with HTTP Basic \
                        (`client_secret_basic`), with `client_secret` in the body (`client_secret_post`), or with \
                        `client_assertion`, depending on its registration.

                        The access token carries the claims of the authorized scope (e.g. `credentialID`, `numSignatures`, \
                        `hashes` and `hashAlgorithmOID` for `credential`).""")
                .requestBody(new RequestBody()
                        .required(true)
                        .content(new Content().addMediaType(FORM_URLENCODED, new MediaType().schema(form))))
                .security(List.of(
                        new SecurityRequirement().addList(CLIENT_SECRET_BASIC),
                        new SecurityRequirement()))
                .responses(new ApiResponses()
                        .addApiResponse("200", new ApiResponse()
                                .description("Access token issued.")
                                .content(jsonContent(ref(SCHEMA_TOKEN_RESPONSE))))
                        .addApiResponse("400", errorResponse(
                                "`invalid_request` (missing or invalid parameter) or `invalid_grant` (invalid, expired "
                                        + "or already used code, or PKCE verification failed)."))
                        .addApiResponse("401", errorResponse("`invalid_client`: client authentication failed.")));
    }

    // ---------------------------------------------------------------------------------------------
    // Discovery endpoints
    // ---------------------------------------------------------------------------------------------

    private Operation jwksOperation() {
        return new Operation()
                .operationId("getJwkSet")
                .addTagsItem(DISCOVERY_TAG)
                .summary("JSON Web Key Set")
                .description("Public keys used to verify the signature of the access tokens issued by this server.")
                .responses(new ApiResponses().addApiResponse("200", new ApiResponse()
                        .description("JWK Set (RFC 7517).")
                        .content(jsonContent(new ObjectSchema()
                                .addProperty("keys", new ArraySchema().items(new ObjectSchema()))))));
    }

    private Operation metadataOperation(String operationId, String summary) {
        return new Operation()
                .operationId(operationId)
                .addTagsItem(DISCOVERY_TAG)
                .summary(summary)
                .description("Issuer and endpoint URLs, and the supported grant types, response types and client "
                        + "authentication methods.")
                .responses(new ApiResponses().addApiResponse("200", new ApiResponse()
                        .description("Server metadata.")
                        .content(jsonContent(new ObjectSchema()))));
    }

    // ---------------------------------------------------------------------------------------------
    // Schemas
    // ---------------------------------------------------------------------------------------------

    private Schema<?> authorizationDetailsSchema() {
        List<String> types = new ArrayList<>();
        types.addAll(OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL);
        types.addAll(OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_CREATION);
        types.addAll(OAuth2AuthorizationDetailsNames.TYPE_CREDENTIAL_DELETE);

        Schema<?> documentDigest = new ObjectSchema()
                .addProperty(OAuth2AuthorizationDetailsNames.HASH, new StringSchema().description("Base64-encoded hash."))
                .addProperty("label", new StringSchema().description("Human-readable name of the document."))
                .addProperty(OAuth2AuthorizationDetailsNames.HASH_TYPE, new StringSchema())
                .addProperty(OAuth2AuthorizationDetailsNames.SIGNED_PROPS, new ArraySchema().items(new ObjectSchema()
                        .addProperty("attribute_name", new StringSchema())
                        .addProperty("attribute_value", new StringSchema())))
                .addProperty(OAuth2AuthorizationDetailsNames.CIRCUMSTANTIAL_DATA, new StringSchema());

        Schema<?> credentialCreationRequest = new ObjectSchema()
                .addProperty(OAuth2AuthorizationDetailsNames.CERTIFICATE_POLICY, new StringSchema())
                .addProperty(OAuth2AuthorizationDetailsNames.SUBJECT_DATA, new StringSchema());

        Schema<?> schema = new ObjectSchema()
                .description("Authorization details object (RFC 9396). The fields depend on `type`.")
                .addProperty(OAuth2AuthorizationDetailsNames.TYPE, new StringSchema()._enum(types))
                .addProperty("locations", new ArraySchema().items(new StringSchema()))
                .addProperty(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID, new StringSchema()
                        .description("`credential` and `credential_deletion` types."))
                .addProperty(OAuth2AuthorizationDetailsNames.SIGNATURE_QUALIFIER, new StringSchema()
                        .description("`credential` type."))
                .addProperty(OAuth2AuthorizationDetailsNames.NUM_SIGNATURES, new StringSchema()
                        .description("`credential` type."))
                .addProperty(OAuth2AuthorizationDetailsNames.HASH_ALGORITHM_OID, new StringSchema()
                        .description("`credential` type."))
                .addProperty(OAuth2AuthorizationDetailsNames.DOCUMENT_DIGESTS, new ArraySchema().items(documentDigest)
                        .description("`credential` type."))
                .addProperty(OAuth2AuthorizationDetailsNames.ACR_VALUES, new ArraySchema().items(new StringSchema())
                        .description("`credential_creation` type."))
                .addProperty(OAuth2AuthorizationDetailsNames.CREDENTIAL_CREATION_REQUEST, credentialCreationRequest
                        .description("`credential_creation` type."));
        schema.setRequired(List.of(OAuth2AuthorizationDetailsNames.TYPE));
        return schema;
    }

    private Schema<?> tokenResponseSchema() {
        Schema<?> schema = new ObjectSchema()
                .addProperty(OAuth2ParameterNames.ACCESS_TOKEN, new StringSchema().description("Access token (JWT)."))
                .addProperty(OAuth2ParameterNames.TOKEN_TYPE, new StringSchema()._enum(List.of("Bearer")))
                .addProperty(OAuth2ParameterNames.EXPIRES_IN, new IntegerSchema().description("Lifetime in seconds."))
                .addProperty(OAuth2ParameterNames.SCOPE, new StringSchema())
                .addProperty(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS, new ArraySchema()
                        .items(ref(SCHEMA_AUTHORIZATION_DETAILS))
                        .description("Authorized details, if the request used `authorization_details`."))
                .addProperty(OAuth2CustomParameterNames.CREDENTIAL_ID, new StringSchema()
                        .description("Authorized credential, if the request used `signatureQualifier`."));
        schema.setRequired(List.of(OAuth2ParameterNames.ACCESS_TOKEN, OAuth2ParameterNames.TOKEN_TYPE));
        return schema;
    }

    private Schema<?> oauth2ErrorSchema() {
        Schema<?> schema = new ObjectSchema()
                .addProperty(OAuth2ParameterNames.ERROR, new StringSchema())
                .addProperty(OAuth2ParameterNames.ERROR_DESCRIPTION, new StringSchema())
                .addProperty(OAuth2ParameterNames.ERROR_URI, new StringSchema().format("uri"));
        schema.setRequired(List.of(OAuth2ParameterNames.ERROR));
        return schema;
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------

    private static QueryParameter queryParameter(String name, boolean required, String description, Schema<?> schema) {
        QueryParameter parameter = new QueryParameter();
        parameter.name(name).required(required).description(description).schema(schema);
        return parameter;
    }

    private static ApiResponse errorResponse(String description) {
        return new ApiResponse().description(description).content(jsonContent(ref(SCHEMA_OAUTH2_ERROR)));
    }

    private static Content jsonContent(Schema<?> schema) {
        return new Content().addMediaType(JSON, new MediaType().schema(schema));
    }

    private static Schema<?> ref(String schemaName) {
        return new Schema<>().$ref("#/components/schemas/" + schemaName);
    }
}
