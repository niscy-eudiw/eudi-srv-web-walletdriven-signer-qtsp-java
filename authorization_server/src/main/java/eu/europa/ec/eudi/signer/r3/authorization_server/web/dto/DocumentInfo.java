package eu.europa.ec.eudi.signer.r3.authorization_server.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DocumentInfo {
	@JsonProperty("label")
	private String label;

	@JsonProperty("hash")
	private String hash;

	@JsonProperty("hashType")
	private String hashType;

	@JsonProperty("signed_props")
	private List<Attribute> signed_props;

	@JsonProperty("circumstantialData")
	private String circumstantialData;

	private static final ObjectMapper MAPPER = new ObjectMapper();

	public DocumentInfo(){}

	public DocumentInfo(String label, String hash){
		this.label = label;
		this.hash = hash;
	}

	public String getHash() {
		return hash;
	}

	public void setHash(String hash) {
		this.hash = hash;
	}

	public String getLabel() {
		return label;
	}

	public void setLabel(String label) {
		this.label = label;
	}

	public String getHashType() {
		return hashType;
	}

	public void setHashType(String hashType) {
		this.hashType = hashType;
	}

	public List<Attribute> getSigned_props() {
		return signed_props;
	}

	public void setSigned_props(List<Attribute> signed_props) {
		this.signed_props = signed_props;
	}

	public String getCircumstantialData() {
		return circumstantialData;
	}

	public void setCircumstantialData(String circumstantialData) {
		this.circumstantialData = circumstantialData;
	}

	public JSONObject toJSON() throws JsonProcessingException {
		return new JSONObject(MAPPER.writeValueAsString(this));
	}
}

@JsonIgnoreProperties(ignoreUnknown = true)
class Attribute{
	@JsonProperty("attribute_name")
	private String attribute_name;
	@JsonProperty("attribute_value")
	private String attribute_value;

	private static final ObjectMapper MAPPER = new ObjectMapper();

	public String getAttribute_name() {
		return attribute_name;
	}

	public void setAttribute_name(String attribute_name) {
		this.attribute_name = attribute_name;
	}

	public String getAttribute_value() {
		return attribute_value;
	}

	public void setAttribute_value(String attribute_value) {
		this.attribute_value = attribute_value;
	}

	public JSONObject toJSON() throws JsonProcessingException {
		return new JSONObject(MAPPER.writeValueAsString(this));
	}
}