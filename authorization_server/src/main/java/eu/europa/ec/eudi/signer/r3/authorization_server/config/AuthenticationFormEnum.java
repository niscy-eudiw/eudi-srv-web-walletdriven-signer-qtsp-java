package eu.europa.ec.eudi.signer.r3.authorization_server.config;

public enum AuthenticationFormEnum {
	LOGIN_FORM(1, "login-form"),
	SAME_DEVICE_FLOW(2, "same-device-flow"),
	CROSS_DEVICE_FLOW(3, "cross-device-flow");

	private final int id;
	private final String value;

	AuthenticationFormEnum(int id, String value) {
		this.id = id;
		this.value = value;
	}

	public int getId() {
		return id;
	}

	public String getValue() {
		return value;
	}
}