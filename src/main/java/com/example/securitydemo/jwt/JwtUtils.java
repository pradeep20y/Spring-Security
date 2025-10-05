package com.example.securitydemo.jwt;

import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret; // Base64-encoded secret used to sign/verify JWTs

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs; // Token expiration time in milliseconds

    /**
     * Extracts JWT from the Authorization header of an HTTP request.
     * 
     * @param request HttpServletRequest containing headers
     * @return the JWT string if present, otherwise null
     * 
     *         Inside:
     *         - request.getHeader("Authorization") fetches the Authorization header
     *         - Checks if it starts with "Bearer "
     *         - Removes "Bearer " prefix to return only the token
     */
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }

    /**
     * Generates a JWT token for the given user.
     * 
     * @param userDetails UserDetails object containing username
     * @return signed JWT token string
     * 
     *         Inside:
     *         - userDetails.getUsername() fetches the username to set as 'sub'
     *         claim
     *         - new Date() sets the issued at (iat) claim
     *         - new Date(currentTime + jwtExpirationMs) sets expiration (exp) claim
     *         - .signWith(key()) signs the token with HMAC using the secret key
     *         - .compact() builds the JWT string
     */
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();

        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    /**
     * Extracts the username (subject) from a JWT token.
     * 
     * @param token JWT string
     * @return username stored in the 'sub' claim
     * 
     *         Inside:
     *         - Jwts.parser() creates a JWT parser builder
     *         - .verifyWith((SecretKey) key()) sets the secret key for signature
     *         verification
     *         - .build() finalizes the parser
     *         - .parseSignedClaims(token) decodes the Base64URL token, verifies
     *         signature, returns Claims
     *         - .getPayload() gets the payload (claims) JSON
     *         - .getSubject() extracts the 'sub' claim (username)
     */
    public String getUserNameFromJwtToken(String token) {
        return Jwts
                .parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    /**
     * Generates the SecretKey object from the Base64-encoded secret string.
     * 
     * @return Key object used for signing/verifying JWT
     * 
     *         Inside:
     *         - Decoders.BASE64.decode(jwtSecret) converts Base64 string to byte[]
     *         - Keys.hmacShaKeyFor(byte[]) returns a SecretKey suitable for HMAC
     *         signing
     */
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * Validates a JWT token.
     * 
     * @param authToken JWT string
     * @return true if token is valid and signature matches; false otherwise
     * 
     *         Inside:
     *         - Jwts.parser().verifyWith((SecretKey)
     *         key()).build().parseSignedClaims(authToken)
     *         → Decodes the token, verifies signature using secret key, returns
     *         claims
     *         - If parsing/verification fails, exception is caught and false is
     *         returned
     */
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return false;
    }

}
