package uk.gov.dwp.dataworks.hive.auth;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.hadoop.conf.Configured;
import org.apache.hive.service.auth.PasswdAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.AuthenticationException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class JwtAuthenticationProvider extends Configured implements PasswdAuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationProvider.class);


    @Override
    public void Authenticate(String user, String password) throws AuthenticationException {

        DecodedJWT decodedJWT;

        try {

            URL keystoreUrl = new URL(System.getenv("COGNITO_KEYSTORE_URL"));

            JwkProvider jwkProvider = new GuavaCachedJwkProvider(new UrlJwkProvider(keystoreUrl));
            decodedJWT = JWT.decode(password);

            Jwk jwk = jwkProvider.get(decodedJWT.getKeyId());

            Algorithm algorithm;
            switch (jwk.getAlgorithm()) {
                case "RS256":
                    algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
                    break;
                case "RS512":
                    algorithm = Algorithm.RSA512((RSAPublicKey) jwk.getPublicKey(), null);
                    break;
                default:
                    logger.error("Unsupported JWK algorithm type {}", jwk.getAlgorithm());
                    throw new AuthenticationException("Unsupported JWK algorithm type " + jwk.getAlgorithm());
            }

            JWTVerifier jwtVerifier = JWT.require(algorithm).build();
            jwtVerifier.verify(decodedJWT);

        } catch (Exception e) {
            logger.error("Error validating JWT token", e);
            throw new AuthenticationException("Error validating JWT token");
        }

        Map<String, Claim> claims = decodedJWT.getClaims();

        String subSuffix;
        if (claims.containsKey("sub")) {
            subSuffix = claims.get("sub").asString().substring(0, 3);
        } else {
            throw new AuthenticationException("Missing sub claim from toke.");
        }

        String jwtUsername;
        if (claims.containsKey("preferred_username")) {
            jwtUsername = claims.get("preferred_username").asString();
            jwtUsername = jwtUsername + subSuffix;
        } else if (claims.containsKey("cognito:username")) {
            jwtUsername = claims.get("cognito:username").asString();
            jwtUsername = jwtUsername + subSuffix;
        } else {
            throw new AuthenticationException("JWT doesn't contain username claim");
        }

        if (!user.equals(jwtUsername)) {
            throw new AuthenticationException(String.format("Attempted impersonation of user %s by user %s", user, jwtUsername));
        }

    }

}
