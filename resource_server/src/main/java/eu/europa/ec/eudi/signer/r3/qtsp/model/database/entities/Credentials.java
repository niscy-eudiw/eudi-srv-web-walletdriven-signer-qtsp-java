package eu.europa.ec.eudi.signer.r3.qtsp.Model;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

public class Credentials {

    private String userID;
    // private String alias;?

    private String id;
    private String description;
    private String signatureQualifier;
    private String SCAL;
    private int multisign;
    private String lang;

    private KeyPair keyPair;
    private String keyStatus;
    private String keyAlgo;
    private String keyLen;
    private String keyCurve;

    private X509Certificate certificate;
    private List<X509Certificate> certificateChain;
    private String certStatus;

    private String authMode;
    private String authExpression;
    private String authObjects;

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSignatureQualifier() {
        return signatureQualifier;
    }

    public void setSignatureQualifier(String signatureQualifier) {
        this.signatureQualifier = signatureQualifier;
    }

    public String getSCAL() {
        return SCAL;
    }

    public void setSCAL(String SCAL) {
        this.SCAL = SCAL;
    }

    public int getMultisign() {
        return multisign;
    }

    public void setMultisign(int multisign) {
        this.multisign = multisign;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public String getKeyStatus() {
        return keyStatus;
    }

    public void setKeyStatus(String keyStatus) {
        this.keyStatus = keyStatus;
    }

    public String getKeyAlgo() {
        return keyAlgo;
    }

    public void setKeyAlgo(String keyAlgo) {
        this.keyAlgo = keyAlgo;
    }

    public String getKeyLen() {
        return keyLen;
    }

    public void setKeyLen(String keyLen) {
        this.keyLen = keyLen;
    }

    public String getKeyCurve() {
        return keyCurve;
    }

    public void setKeyCurve(String keyCurve) {
        this.keyCurve = keyCurve;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(List<X509Certificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    public String getCertStatus() {
        return certStatus;
    }

    public void setCertStatus(String certStatus) {
        this.certStatus = certStatus;
    }

    public String getAuthMode() {
        return authMode;
    }

    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    public String getAuthExpression() {
        return authExpression;
    }

    public void setAuthExpression(String authExpression) {
        this.authExpression = authExpression;
    }

    public String getAuthObjects() {
        return authObjects;
    }

    public void setAuthObjects(String authObjects) {
        this.authObjects = authObjects;
    }

    @Override
    public String toString() {
        return "Credentials{" +
                "id='" + id + '\'' +
                ", description='" + description + '\'' +
                ", signatureQualifier='" + signatureQualifier + '\'' +
                ", SCAL2='" + SCAL + '\'' +
                ", multisign=" + multisign +
                ", lang='" + lang + '\'' +
                ", keyPair=" + keyPair +
                ", keyStatus='" + keyStatus + '\'' +
                ", keyAlgo='" + keyAlgo + '\'' +
                ", keyLen='" + keyLen + '\'' +
                ", keyCurve='" + keyCurve + '\'' +
                ", certificate=" + certificate +
                ", certificateChain=" + certificateChain +
                ", certStatus='" + certStatus + '\'' +
                ", authMode='" + authMode + '\'' +
                ", authExpression='" + authExpression + '\'' +
                ", authObjects='" + authObjects + '\'' +
                '}';
    }
}
