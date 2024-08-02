package eu.europa.ec.eudi.signer.r3.authorization_server.web.oid4vp.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class JwtProvider {

    private static final String TYPE_CLAIM_NAME = "type";
    private static final Logger log = LoggerFactory.getLogger(JwtProvider.class);

    private long lifetimeMinutes = 600L;
    private String tokenSecret;
    private String type = "userAuthentication";

    public long getLifetimeMinutes() {
        return lifetimeMinutes;
    }

    public void setLifetimeMinutes(long lifetimeMinutes) {
        this.lifetimeMinutes = lifetimeMinutes;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public JwtToken createToken(String subject) {

        // Use java8 time library for better expiry handling
        Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = issuedAt.plus(this.lifetimeMinutes, ChronoUnit.MINUTES);

        log.debug("Issued JWT token at: {}, expires at: {}", issuedAt, expiration);
        log.info("Issued JWT token at: {}", issuedAt);

        JwtToken token = new JwtToken(this.type, subject);

        String rawToken = Jwts.builder()
              .setSubject(subject)
              .setIssuedAt(Date.from(issuedAt))
              .setExpiration(Date.from(expiration))
              .claim(TYPE_CLAIM_NAME, this.type)
              .signWith(SignatureAlgorithm.HS512, this.tokenSecret)
              .compact();
        token.setRawToken(rawToken);
        return token;
    }

    public JwtToken parseToken(String rawToken) {
        Claims claims = Jwts.parser()
              .setSigningKey(this.tokenSecret)
              .parseClaimsJws(rawToken)
              .getBody();

        JwtToken token = new JwtToken(claims.getSubject(),
              claims.get(TYPE_CLAIM_NAME).toString());
        token.setRawToken(rawToken);
        return token;
    }

    public JwtToken validateToken(String rawToken) {
        try {
            JwtToken token = parseToken(rawToken);
            if (!token.getType().equals(this.type)) {
                return JwtToken.invalidToken(
                      String.format("Unexpected token type: should be of type %s",
                            this.type));
            } else {
                return token;
            }
        } catch (SignatureException ex) {
            return JwtToken.invalidToken("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            return JwtToken.invalidToken("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            return JwtToken.expiredToken();
        } catch (UnsupportedJwtException ex) {
            return JwtToken.invalidToken("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            return JwtToken.invalidToken("JWT claims string is empty.");
        }
    }

}
