package eu.europa.ec.eudi.signer.r3.qtsp.model.database.entities;

import jakarta.persistence.*;

import java.security.PublicKey;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

@Entity
@Table(name="credentials")
public class Credentials {

    private String userID;
    // private String alias;?

    @Id
    private String id;
    private String description;
    private String signatureQualifier;
    private String SCAL;
    private int multisign;
    private String lang;
    // private key wrapped in the HSM base 64 encoded
    @Column(length = 2000)
    private String privateKey;
    // public key base 64 encoded
    @Column(length = 2000)
    private String publicKey;
    private String keyStatus;
    private List<String> keyAlgo;
    private int keyLen;
    private String keyCurve;
    @Column(length = 2000)
    private String certificate;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "credential", cascade = CascadeType.ALL)
    private List<CertificateChain> certificateChain;
    private String certStatus;
    private String authMode;
    private String authExpression;
    private List<Object> authObjects;

    public Credentials(){
        this.id = UUID.randomUUID().toString();
    }

    public boolean isValid(){
        return this.keyStatus.equals("enabled") && this.certStatus.equals("valid");
    }

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

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getKeyStatus() {
        return keyStatus;
    }

    public void setKeyStatus(String keyStatus) {
        this.keyStatus = keyStatus;
    }

    public List<String> getKeyAlgo() {
        return keyAlgo;
    }

    public void setKeyAlgo(List<String> keyAlgo) {
        this.keyAlgo = keyAlgo;
    }

    public int getKeyLen() {
        return keyLen;
    }

    public void setKeyLen(int keyLen) {
        this.keyLen = keyLen;
    }

    public String getKeyCurve() {
        return keyCurve;
    }

    public void setKeyCurve(String keyCurve) {
        this.keyCurve = keyCurve;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public List<String> getCertificateChain() {
        return this.certificateChain.stream().map(CertificateChain::getCertificate).collect(Collectors.toList());
    }

    public void setCertificateChain(List<CertificateChain> certificateChain) {
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

    public List<Object> getAuthObjects() {
        return authObjects;
    }

    public void setAuthObjects(List<Object> authObjects) {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Credentials)) return false;
        Credentials that = (Credentials) o;
        return multisign == that.multisign && keyLen == that.keyLen && Objects.equals(userID, that.userID) &&
              Objects.equals(signatureQualifier, that.signatureQualifier) && Objects.equals(SCAL, that.SCAL) &&
              Objects.equals(lang, that.lang) && Objects.deepEquals(privateKey, that.privateKey) &&
              Objects.deepEquals(publicKey, that.publicKey) && Objects.equals(keyStatus, that.keyStatus) &&
              Objects.equals(keyAlgo, that.keyAlgo) && Objects.equals(keyCurve, that.keyCurve) &&
              Objects.equals(certificate, that.certificate) && Objects.equals(certificateChain, that.certificateChain)
              && Objects.equals(certStatus, that.certStatus) && Objects.equals(authMode, that.authMode);
    }


}
