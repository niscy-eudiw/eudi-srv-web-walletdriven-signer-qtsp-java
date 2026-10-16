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

import eu.europa.ec.eudi.signer.r3.authorization_server.model.authorization_details.OAuth2AuthorizationDetailsNames;

/**
 * OpenAPI documentation of the OAuth2 endpoints exposed by the Authorization
 * Server.
 * <p>
 * The OAuth2 endpoints are implemented as Spring Authorization Server filters,
 * not as controllers, so springdoc cannot discover them. Their paths,
 * parameters and responses are therefore described explicitly here, following
 * the custom request converters (AuthorizationCodeRequestConverter and
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
                                + "Resource Server (CSC API v2.2.0.0). Users are authenticated through OpenID4VP.")
                        .version("v1"))
                .servers(List.of(new Server().url(serviceURLConfig.getServiceURL())))
                .tags(List.of(
                        new Tag().name(OAUTH2_TAG).description("Authorization Code flow with PKCE")))
                .components(new Components()
                        .addSecuritySchemes(CLIENT_SECRET_BASIC, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("basic")
                                .description("Client authentication with client_id and client_secret")));
    }

    /**
     * The schemas are registered here, together with the paths that reference
     * them: springdoc removes unreferenced schemas before running the
     * customizers, so schemas declared on the OpenAPI bean are lost.
     */
    private OpenApiCustomizer oauth2Endpoints(AuthorizationServerSettings settings) {
        return openApi -> {
            openApi.getComponents()
                    .addSchemas(SCHEMA_AUTHORIZATION_DETAILS, authorizationDetailsSchema())
                    .addSchemas(SCHEMA_TOKEN_RESPONSE, tokenResponseSchema())
                    .addSchemas(SCHEMA_OAUTH2_ERROR, oauth2ErrorSchema());
            openApi
                    .path(settings.getAuthorizationEndpoint(), new PathItem().get(authorizeOperation()))
                    .path(settings.getTokenEndpoint(), new PathItem().post(tokenOperation()));
        };
    }

    // ---------------------------------------------------------------------------------------------
    // GET /oauth2/authorize
    // ---------------------------------------------------------------------------------------------
    private Operation authorizeOperation() {
        Operation operation = new Operation()
                .operationId("authorize")
                .addTagsItem(OAUTH2_TAG)
                .summary("Authorization request (CSC API v2.2.0.0, section 8.2.2)")
                .description("""
                        OAuth 2.0 authorization endpoint, processing Authorization Code flow requests with PKCE (RFC 6749, \
                        RFC 7636). If the user is not authenticated, they are redirected to the authentication method \
                        configured for the client (OpenID4VP same-device or cross-device). After a successful authorization, \
                        the user agent is redirected to `redirect_uri` with `code` and, if sent, `state`.

                        The requested authorization is defined by **either** `scope` **or** `authorization_details`, \
                        never both:
                        * `scope=service` (default when neither is present): service authorization to access the CSC API.
                        * `scope=credential`: credential authorization to sign. Detailed with `credentialID` and/or \
                        `signatureQualifier`, `numSignatures`, `hashes` and `hashAlgorithmOID`. If the credential's `SCAL` \
                        is `2`, `hashes` is required.
                        * `scope=credential-creation` / `scope=credential-deletion`: authorization to create or delete a credential.
                        * `authorization_details` (RFC 9396): a JSON array of `AuthorizationDetails` objects of type \
                        `credential`, `credential-creation` or `credential-deletion` (or their \
                        `https://cloudsignatureconsortium.org/2025/...` URI forms, which are recommended). It SHOULD be preferred over `scope`, \
                        since it carries more detail about the documents to be signed.

                        An access token with `credential` scope also grants service authorization for `credentials/info` \
                        and `signatures/signHash`; with `credential-creation` for `credentials/create`; and with \
                        `credential-deletion` for `credentials/delete`.

                        Alternatively, when the authorization request was pushed (RFC 9126), only `client_id` and \
                        `request_uri` are sent.""");

        // Input parameters defined in OAuth 2.0
        operation.addParametersItem(queryParameter(OAuth2ParameterNames.RESPONSE_TYPE, true,
                "Must be `code` (RFC 6749, section 4.1.1).", new StringSchema()._enum(List.of("code"))));
        operation.addParametersItem(queryParameter(OAuth2ParameterNames.CLIENT_ID, true,
                "Identifier of the registered client (RFC 6749, section 4.1.1).", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2ParameterNames.REDIRECT_URI, false,
                "URL where the user is redirected after the authorization. Must exactly match one of the redirect URIs "
                + "registered for the client. If omitted, the default redirect URI registered for the client is used.",
                new StringSchema().format("uri")));
        operation.addParametersItem(queryParameter(OAuth2ParameterNames.SCOPE, false,
                "Scope of the access request (RFC 6749, section 3.3). Defaults to `service` if neither `scope` nor "
                + "`authorization_details` is present. Must not be present if `authorization_details` is present.",
                new StringSchema()._enum(List.of(OAuth2ScopesNames.SERVICE, OAuth2ScopesNames.CREDENTIAL,
                        OAuth2ScopesNames.CREDENTIAL_CREATION, OAuth2ScopesNames.CREDENTIAL_DELETION))));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS, false,
                "URL-encoded JSON array (RFC 9396) of `AuthorizationDetails` objects. Must not be present if `scope` "
                + "is present.", new StringSchema()));
        operation.addParametersItem(queryParameter(PkceParameterNames.CODE_CHALLENGE, true,
                "PKCE code challenge binding the transaction to the user agent (RFC 7636).", new StringSchema()));
        operation.addParametersItem(queryParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, false,
                "PKCE code verifier transformation method (RFC 7636). `S256` is recommended.",
                new StringSchema()._enum(List.of("S256", "plain"))._default("plain")));
        operation.addParametersItem(queryParameter(OAuth2ParameterNames.STATE, false,
                "Opaque value returned unchanged in the redirect to the client (RFC 6749, section 4.1.1).", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.REQUEST_URI, false,
                "Reference to a pushed authorization request (RFC 9126). Required when the request was pushed; "
                + "in that case only `client_id` may be sent with it.", new StringSchema()));

        // Input parameters defined in the CSC API
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.LANG, false,
                "Preferred language of the authorization page (RFC 5646). Must not be used with `authorization_details`.",
                new StringSchema()).example("en-US"));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.CLIENT_DATA, false,
                "Arbitrary data from the signature application. Must not be used with "
                + "`authorization_details`.", new StringSchema()));

        // Input parameters of the "credential" scope
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.CREDENTIAL_ID, false,
                "`scope=credential` only. Identifier of the credential to authorize, URL encoded. At least one of "
                + "`credentialID` and `signatureQualifier` is required.", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.SIGNATURE_QUALIFIER, false,
                "`scope=credential` only. Identifier of the kind of signature to create. At least one of "
                + "`credentialID` and `signatureQualifier` is required.", new StringSchema()).example("eu_eidas_qes"));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.NUM_SIGNATURES, false,
                "`scope=credential` only (required). Number of signatures to authorize.",
                new IntegerSchema().minimum(java.math.BigDecimal.ONE)));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.HASHES, false,
                "`scope=credential` only. Comma-separated list of base64url-encoded hashes to sign, binding the access "
                + "token to them. Required if the credential's `SCAL` is `2`; the order does not need to match the one "
                + "used in `signatures/signHash`.", new StringSchema()));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.HASH_ALGORITHM_OID, false,
                "`scope=credential` only. OID of the algorithm used to compute the hashes. Required with `hashes`.",
                new StringSchema()).example("2.16.840.1.101.3.4.2.1"));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.DESCRIPTION, false,
                "`scope=credential` only. Free-form description of the authorization transaction, in the `lang` language.",
                new StringSchema().maxLength(500)));
        operation.addParametersItem(queryParameter(OAuth2CustomParameterNames.ACCOUNT_TOKEN, false,
                "`scope=credential` only. JWT (RFC 7519) restricting access to the authorization server to registered "
                + "accounts (CSC API, section 8.2.1). Signed with HS256, using the SHA-256 hash of the client secret as key.",
                new StringSchema()));

        return operation.responses(new ApiResponses()
                .addApiResponse("302", new ApiResponse()
                        .description("""
                                Redirect to the authentication page, if the user is not authenticated. Otherwise, redirect \
                                to `redirect_uri` with the following query parameters (`application/x-www-form-urlencoded`):
                                * on success: `code` (short-lived, single-use, bound to the client and the redirect URI) \
                                and `state`, if sent in the request;
                                * on error: `error` (`invalid_request`, `access_denied`, `unsupported_response_type`, \
                                `invalid_scope`, `server_error` or `temporarily_unavailable`), optionally \
                                `error_description` and `error_uri`, and `state`, if sent in the request.""")
                        .addHeaderObject("Location", new Header()
                                .description("`{redirect_uri}?code={authorization_code}&state={state}` or "
                                        + "`{redirect_uri}?error={error}&error_description={description}&state={state}`")
                                .schema(new StringSchema().format("uri"))))
                .addApiResponse("400", errorResponse(
                        "`invalid_request`: the client or the redirect URI is missing or invalid, so the error cannot be "
                        + "returned to the client.")));
    }

    // ---------------------------------------------------------------------------------------------
    // POST /oauth2/token
    // ---------------------------------------------------------------------------------------------
    private Operation tokenOperation() {
        Schema<?> form = new ObjectSchema()
                // Input parameters defined in OAuth 2.0
                .addProperty(OAuth2ParameterNames.GRANT_TYPE, new StringSchema()
                        ._enum(List.of("authorization_code"))
                        .description("Grant type. Only the Authorization Code grant (`authorization_code`) is supported."))
                .addProperty(OAuth2ParameterNames.CODE, new StringSchema()
                        .description("Authorization code returned by the authorization endpoint. Bound to the client and "
                                + "the redirect URI."))
                .addProperty(OAuth2ParameterNames.CLIENT_ID, new StringSchema()
                        .description("Identifier of the client, as sent to the authorization endpoint."))
                .addProperty(OAuth2ParameterNames.CLIENT_SECRET, new StringSchema()
                        .description("Client secret (`client_secret_post`). Required if the client authenticates with a "
                                + "client secret and does not use the `Authorization` header. Not recommended "
                                + "(RFC 6749, section 2.3.1)."))
                .addProperty(OAuth2ParameterNames.CLIENT_ASSERTION, new StringSchema()
                        .description("Assertion authenticating the client. Required if the client authenticates with "
                                + "client assertions."))
                .addProperty(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, new StringSchema().format("uri")
                        ._enum(List.of("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
                        .description("Format of the assertion. Required with `client_assertion`."))
                .addProperty(OAuth2ParameterNames.REDIRECT_URI, new StringSchema().format("uri")
                        .description("Required if `redirect_uri` was sent in the authorization request, and must be "
                                + "identical to it."))
                .addProperty(PkceParameterNames.CODE_VERIFIER, new StringSchema()
                        .description("PKCE code verifier matching the `code_challenge` of the authorization request "
                                + "(RFC 7636)."))
                .addProperty(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS, new StringSchema()
                        .description("JSON array (RFC 9396) of the authorization details approved during the "
                                + "authorization. Required if `authorization_details` was used in the authorization request."))
                // Input parameters defined in the CSC API
                .addProperty(OAuth2CustomParameterNames.CLIENT_DATA, new StringSchema()
                        .description("Arbitrary data from the signature application."));
        form.setRequired(List.of(OAuth2ParameterNames.GRANT_TYPE, OAuth2ParameterNames.CODE,
                OAuth2ParameterNames.CLIENT_ID, PkceParameterNames.CODE_VERIFIER));

        return new Operation()
                .operationId("token")
                .addTagsItem(OAUTH2_TAG)
                .summary("Access token request (CSC API v2.2.0.0, section 8.2.4)")
                .description("""
                        OAuth 2.0 token endpoint. Exchanges an authorization code for a bearer access token (JWT). The \
                        parameters are sent as `application/x-www-form-urlencoded` (UTF-8).

                        The client authenticates with HTTP Basic (`client_secret_basic`), with `client_secret` in the body \
                        (`client_secret_post`) or with `client_assertion`, depending on its registration.

                        The access token is sent in the `Authorization: Bearer` header of the subsequent CSC API requests. \
                        An access token with `credential` scope can also be sent as the `SAD` parameter of \
                        `signatures/signHash` and `signatures/signDoc`.""")
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
                        .addApiResponse("400", errorResponse("""
                                * `invalid_request`: missing `client_id`, `grant_type` or `code`, invalid `client_id` or \
                                `grant_type`, or invalid `client_secret`.
                                * `invalid_grant`: invalid, expired or already used `code`, `redirect_uri` not matching the \
                                one of the authorization request, or PKCE verification failed."""))
                        .addApiResponse("401", errorResponse(
                                "`invalid_client`: client authentication missing or failed.")));
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
                .addProperty(OAuth2AuthorizationDetailsNames.HASH, new StringSchema()
                        .description("Base64-encoded hash of the document."))
                .addProperty("label", new StringSchema().description("Human-readable name of the document."))
                .addProperty(OAuth2AuthorizationDetailsNames.HASH_TYPE, new StringSchema()
                        .description("Type of the hash (see `supportedHashTypes` in `info`)."))
                .addProperty(OAuth2AuthorizationDetailsNames.SIGNED_PROPS, new ArraySchema()
                        .items(new ObjectSchema().additionalProperties(new StringSchema()))
                        .description("Signed attributes to include in the signature, as name/value objects."))
                .addProperty(OAuth2AuthorizationDetailsNames.CIRCUMSTANTIAL_DATA, new StringSchema()
                        .description("Circumstantial data used to compute the hash."));
        documentDigest.setRequired(List.of(OAuth2AuthorizationDetailsNames.HASH));

        Schema<?> credentialCreationRequest = new ObjectSchema()
                .description("`credential-creation` type (required). Certificate policy and subject data to authorize "
                        + "(CSC data model).")
                .addProperty(OAuth2AuthorizationDetailsNames.CERTIFICATE_POLICY, new StringSchema()
                        .description("OID of the certificate policy of the new credential."))
                .addProperty(OAuth2AuthorizationDetailsNames.SUBJECT_DATA, new StringSchema()
                        .description("Subject data of the certificate."));
        credentialCreationRequest.setRequired(List.of(OAuth2AuthorizationDetailsNames.CERTIFICATE_POLICY));

        Schema<?> schema = new ObjectSchema()
                .description("""
                        Authorization details object (RFC 9396). The fields depend on `type`:
                        * `credential`: `signatureCreationApproval` fields (`credentialID` and/or `signatureQualifier`, \
                        `numSignatures`, `documentDigests`, `hashAlgorithmOID`) and `locations`.
                        * `credential-creation`: `credentialCreationRequest` and `acr_values`.
                        * `credential-deletion`: `credentialID`.""")
                .addProperty(OAuth2AuthorizationDetailsNames.TYPE, new StringSchema()._enum(types)
                        .description("Authorization details type. The `https://cloudsignatureconsortium.org/2025/...` "
                                + "URI forms are recommended."))
                .addProperty(OAuth2AuthorizationDetailsNames.LOCATIONS, new ArraySchema().items(new StringSchema())
                        .description("`credential` type. Locations of the APIs to which access is authorized."))
                .addProperty(OAuth2AuthorizationDetailsNames.CREDENTIAL_ID, new StringSchema()
                        .description("`credential` type: credential to authorize (at least one of `credentialID` and "
                                + "`signatureQualifier` is required). `credential-deletion` type (required): credential "
                                + "to delete."))
                .addProperty(OAuth2AuthorizationDetailsNames.SIGNATURE_QUALIFIER, new StringSchema()
                        .description("`credential` type. Kind of signature to create."))
                .addProperty(OAuth2AuthorizationDetailsNames.NUM_SIGNATURES, new IntegerSchema()
                        .minimum(java.math.BigDecimal.ONE)
                        .description("`credential` type. Number of signatures to authorize."))
                .addProperty(OAuth2AuthorizationDetailsNames.DOCUMENT_DIGESTS, new ArraySchema().items(documentDigest)
                        .description("`credential` type. Documents to sign."))
                .addProperty(OAuth2AuthorizationDetailsNames.HASH_ALGORITHM_OID, new StringSchema()
                        .description("`credential` type. OID of the algorithm used to compute the `documentDigests` hashes."))
                .addProperty(OAuth2AuthorizationDetailsNames.ACR_VALUES, new ArraySchema().items(new StringSchema())
                        .description("`credential-creation` type. Requested Authentication Context Class References, "
                                + "controlling how the user authenticates for certificate issuance."))
                .addProperty(OAuth2AuthorizationDetailsNames.CREDENTIAL_CREATION_REQUEST, credentialCreationRequest);
        schema.setRequired(List.of(OAuth2AuthorizationDetailsNames.TYPE));
        return schema;
    }

    private Schema<?> tokenResponseSchema() {
        Schema<?> schema = new ObjectSchema()
                .addProperty(OAuth2ParameterNames.ACCESS_TOKEN, new StringSchema()
                        .description("Short-lived access token (JWT), sent as `Authorization: Bearer` in the subsequent "
                                + "API requests."))
                .addProperty(OAuth2ParameterNames.TOKEN_TYPE, new StringSchema()._enum(List.of("Bearer"))
                        .description("Access token type (RFC 6749)."))
                .addProperty(OAuth2ParameterNames.EXPIRES_IN, new IntegerSchema()
                        .description("Lifetime of the access token in seconds. Defaults to 3600 if omitted."))
                .addProperty(OAuth2ParameterNames.SCOPE, new StringSchema().description("Authorized scope."))
                .addProperty(OAuth2CustomParameterNames.AUTHORIZATION_DETAILS, new ArraySchema()
                        .items(ref(SCHEMA_AUTHORIZATION_DETAILS))
                        .description("Authorization details approved during the authorization, if the request used "
                                + "`authorization_details`. If a `signatureQualifier` was resolved to a credential, it "
                                + "contains the `credentialID`."))
                .addProperty(OAuth2CustomParameterNames.CREDENTIAL_ID, new StringSchema()
                        .description("Credential selected during the authorization, if the request used `scope=credential` "
                                + "with `signatureQualifier`."));
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
