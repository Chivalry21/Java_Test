package org.example;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;


    public class JWTVerificationTest {

        // Generate a secret key for JWT (Use a secure method for your production code)
        private static final SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

        @Test
        public void testValidTokenVerification() {
            String username = "Gabriel";
            String validToken = generateJWT(username);
            String verificationResult = verifyToken(validToken);
            assertEquals("verification pass", verificationResult);
        }

        @Test
        public void testInvalidTokenVerification() {
            String invalidToken = "invalid_token_here";
            String verificationResult = verifyToken(invalidToken);
            assertEquals("verification fails", verificationResult);
        }

        @Test
        public void testExpiredTokenVerification() {
            String username = "expiredUser";
            String expiredToken = generateExpiredJWT(username);
            String verificationResult = verifyToken(expiredToken);
            assertEquals("verification fails: token has expired", verificationResult);
        }

        private String generateJWT(String username) {
            return Jwts.builder()
                    .setSubject(username)
                    .signWith(secretKey, SignatureAlgorithm.HS256)
                    .compact();
        }

        private String generateExpiredJWT(String username) {
            return Jwts.builder()
                    .setSubject(username)
                    .setExpiration(new Date(System.currentTimeMillis() - 1000))
                    .signWith(secretKey, SignatureAlgorithm.HS256)
                    .compact();
        }

        private String verifyToken(String jwtToken) {
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(secretKey)
                        .build()
                        .parseClaimsJws(jwtToken)
                        .getBody();

                // If verification succeeds, return "verification pass"
                return "verification pass";
            } catch (ExpiredJwtException e) {
                return "verification fails: token has expired";
            } catch (Exception e) {
                return "verification fails";
            }
        }
    }


