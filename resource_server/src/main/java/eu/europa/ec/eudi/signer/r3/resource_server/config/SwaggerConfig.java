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
import io.swagger.v3.oas.models.tags.Tag;
import java.util.List;
import java.util.function.Consumer;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI documentation of the CSC API v2 endpoints exposed by the Resource Server.
 * <p>
 * The endpoints are discovered by springdoc from the controllers. This configuration completes them
 * with what cannot be inferred from the code: the OAuth2 scope required by each endpoint (see WebSecurity),
 * the actual response status codes and the format of the error responses (see GlobalExceptionHandler).
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
	private static final String SCOPE_CREDENTIAL_CREATION = "credential_creation";
	private static final String SCOPE_CREDENTIAL_DELETION = "credential_deletion";

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
	OpenAPI customOpenAPI(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String authorizationServerUrl) {
		return new OpenAPI()
			  .info(new Info()
					.title("EUDI Wallet-Driven Signer QTSP - Resource Server")
					.description("Cloud Signature Consortium (CSC) API v2 for credential management and remote signing "
						  + "of hashes. Except for `/csc/v2/info`, the endpoints require an access token issued by the "
						  + "Authorization Server for the scope indicated in each endpoint.")
					.version("v1"))
			  .tags(List.of(
					new Tag().name(INFO_TAG).description("Information about the service"),
					new Tag().name(CREDENTIALS_TAG).description("Management of the user's credentials (key pair and certificate)"),
					new Tag().name(SIGNATURES_TAG).description("Signature of hashes")))
			  .components(new Components()
					.addSecuritySchemes(OAUTH2, new SecurityScheme()
						  .type(SecurityScheme.Type.OAUTH2)
						  .description("Authorization Code flow with PKCE. Requests for the `credential`, `credential_creation` "
								+ "and `credential_deletion` scopes also need `authorization_details` (or the CSC parameters), "
								+ "which are not supported by the Swagger UI authorization dialog: obtain the token from the "
								+ "Authorization Server and use `bearerAuth` instead.")
						  .flows(new OAuthFlows().authorizationCode(new OAuthFlow()
								.authorizationUrl(authorizationServerUrl + "/oauth2/authorize")
								.tokenUrl(authorizationServerUrl + "/oauth2/token")
								.scopes(new Scopes()
									  .addString(SCOPE_SERVICE, "Access to the credentials of the user")
									  .addString(SCOPE_CREDENTIAL, "Signature of the authorized hashes with the authorized credential")
									  .addString(SCOPE_CREDENTIAL_CREATION, "Creation of a new credential")
									  .addString(SCOPE_CREDENTIAL_DELETION, "Deletion of the authorized credential")))))
					.addSecuritySchemes(BEARER_AUTH, new SecurityScheme()
						  .type(SecurityScheme.Type.HTTP)
						  .scheme("bearer")
						  .bearerFormat("JWT")
						  .description("Access token issued by the Authorization Server"))
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
				  .summary("Get information about the service")
				  .description("Returns the information about the service and the list of API methods it supports. "
						+ "Does not require authentication.")
				  .security(List.of())
				  .requestBody(operation.getRequestBody().content(jsonContent(new ObjectSchema()
						.addProperty("lang", new StringSchema()
							  .description("Requested language for the response (RFC 5646).")
							  .example("en-US"))))));

			document(openApi, "/csc/v2/credentials/list", operation -> operation
				  .operationId("credentialsList")
				  .tags(List.of(CREDENTIALS_TAG))
				  .summary("List the credentials of the user")
				  .description("Returns the list of credentials of the user. If the user has no active credential, a new one "
						+ "is created first. The access token must contain the user's identity claims.")
				  .security(scopes(SCOPE_SERVICE, SCOPE_CREDENTIAL, SCOPE_CREDENTIAL_CREATION, SCOPE_CREDENTIAL_DELETION))
				  .responses(errorResponses().addApiResponse("200", ok(operation,
						"Credentials of the user."))));

			document(openApi, "/csc/v2/credentials/info", operation -> operation
				  .operationId("credentialsInfo")
				  .tags(List.of(CREDENTIALS_TAG))
				  .summary("Get information about a credential")
				  .description("Returns the information about a credential of the user: key, certificate and authorization mode.")
				  .security(scopes(SCOPE_SERVICE, SCOPE_CREDENTIAL, SCOPE_CREDENTIAL_CREATION, SCOPE_CREDENTIAL_DELETION))
				  .responses(errorResponses().addApiResponse("200", ok(operation,
						"Information about the credential."))));

			document(openApi, "/csc/v2/credentials/create", operation -> operation
				  .operationId("credentialsCreate")
				  .tags(List.of(CREDENTIALS_TAG))
				  .summary("Create a credential")
				  .description("Creates a new ECDSA P-256 key pair and issues its certificate. The certificate subject is taken "
						+ "from `credentialCreationRequest.subjectData` or, if absent, from the identity claims of the access token.")
				  .security(scopes(SCOPE_CREDENTIAL_CREATION))
				  .responses(errorResponses().addApiResponse("201", new ApiResponse()
						.description("Credential created. The body contains the credential information only if "
							  + "`credentialInfo` is `true`.")
						.content(jsonContent(new Schema<>().$ref("#/components/schemas/" + credentialInfoSchema))))));

			document(openApi, "/csc/v2/credentials/delete", operation -> operation
				  .operationId("credentialsDelete")
				  .tags(List.of(CREDENTIALS_TAG))
				  .summary("Delete a credential")
				  .description("Deletes a credential of the user. The `credentialID` must be the one authorized in the access token.")
				  .security(scopes(SCOPE_CREDENTIAL_DELETION))
				  .responses(errorResponses().addApiResponse("204", new ApiResponse().description("Credential deleted."))));

			document(openApi, "/csc/v2/signatures/signHash", operation -> operation
				  .operationId("signaturesSignHash")
				  .tags(List.of(SIGNATURES_TAG))
				  .summary("Sign hashes")
				  .description("Signs one or more hashes with a credential of the user. The `credentialID`, `hashes` and "
						+ "`hashAlgorithmOID` must match the ones authorized in the access token, and the number of hashes "
						+ "cannot exceed the authorized `numSignatures`. Only the synchronous `operationMode` (`S`) is supported.")
				  .security(scopes(SCOPE_CREDENTIAL))
				  .responses(errorResponses().addApiResponse("200", ok(operation,
						"Signature values, in the same order as the hashes in the request."))));
		};
	}

	private static void document(OpenAPI openApi, String path, Consumer<Operation> customizer) {
		PathItem pathItem = openApi.getPaths() == null ? null : openApi.getPaths().get(path);
		if (pathItem != null && pathItem.getPost() != null)
			customizer.accept(pathItem.getPost());
	}

	/** The 200 response generated by springdoc from the controller return type, with the given description. */
	private static ApiResponse ok(Operation operation, String description) {
		ApiResponse response = operation.getResponses() == null ? null : operation.getResponses().get("200");
		return (response == null ? new ApiResponse() : response).description(description);
	}

	/** Access token with one of the given scopes, obtained with the OAuth2 flow or provided directly. */
	private static List<SecurityRequirement> scopes(String... scopes) {
		return List.of(
			  new SecurityRequirement().addList(OAUTH2, List.of(scopes)),
			  new SecurityRequirement().addList(BEARER_AUTH));
	}

	/** Errors returned by Spring Security and by the GlobalExceptionHandler. */
	private static ApiResponses errorResponses() {
		ApiResponse badRequest = new ApiResponse()
			  .description("Invalid request: missing or invalid parameter, or request not authorized by the access token.")
			  .content(jsonContent(new Schema<>().$ref("#/components/schemas/" + SCHEMA_ERROR)));
		return new ApiResponses()
			  .addApiResponse("400", badRequest)
			  .addApiResponse("401", new ApiResponse().description("Missing, invalid or expired access token."))
			  .addApiResponse("403", new ApiResponse().description("The access token does not have the required scope."));
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
