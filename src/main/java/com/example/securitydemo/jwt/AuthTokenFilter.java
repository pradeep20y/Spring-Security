package com.example.securitydemo.jwt;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * AuthTokenFilter is a Spring Security filter that executes once per HTTP
 * request.
 * 
 * <p>
 * Its purpose is to:
 * 1. Extract the JWT from the Authorization header.
 * 2. Validate the JWT token signature and expiration.
 * 3. Extract the username from the JWT claims.
 * 4. Load the full UserDetails from the database or in-memory store.
 * 5. Create an Authentication object and set it in the SecurityContext for the
 * current thread.
 * 
 * <p>
 * This allows Spring Security to know which user is authenticated and what
 * roles/authorities they have
 * for the duration of the current request.
 */
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils; // Utility class for JWT operations (parse, validate, generate)

    @Autowired
    private UserDetailsService userDetailsService; // Service to load user information by username

    /**
     * Filters each incoming HTTP request to process JWT authentication.
     * 
     * @param request     The HTTP request.
     * @param response    The HTTP response.
     * @param filterChain The filter chain to continue processing.
     * @throws ServletException If a servlet-specific error occurs.
     * @throws IOException      If an I/O error occurs.
     * 
     *                          Inside this method:
     *                          1. Extract JWT from the Authorization header using
     *                          parseJwt(request).
     *                          2. If JWT is present and valid:
     *                          a. Extract username from JWT claims.
     *                          b. Load UserDetails for the username.
     *                          c. Create a UsernamePasswordAuthenticationToken
     *                          containing UserDetails and authorities.
     *                          d. Set request-specific details in the
     *                          authentication object.
     *                          e. Store authentication in SecurityContextHolder
     *                          (thread-local storage for current request).
     *                          3. Pass the request along the filter chain using
     *                          filterChain.doFilter().
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request); // Step 1: Extract JWT from header
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) { // Step 2: Validate JWT
                String username = jwtUtils.getUserNameFromJwtToken(jwt); // Step 3: Extract username

                UserDetails userDetails = userDetailsService.loadUserByUsername(username); // Step 4: Load UserDetails

                // Step 5: Create Authentication object with user details and roles
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                // Step 6: Set request-specific details (IP, session info)
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Step 7: Store Authentication object in SecurityContextHolder for current
                // thread/request
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            // Log any errors during JWT parsing, validation, or authentication setup
            System.out.println(e.getMessage());
        }

        // Step 8: Continue filter chain to allow request to reach controller
        filterChain.doFilter(request, response);
    }

    /**
     * Extracts the JWT from the Authorization header of the HTTP request.
     * 
     * @param request The HTTP request.
     * @return The JWT string if present; otherwise null.
     * 
     *         Inside:
     *         - Calls jwtUtils.getJwtFromHeader(request) which:
     *         a. Reads the "Authorization" header.
     *         b. Checks if it starts with "Bearer ".
     *         c. Returns the token part after "Bearer ".
     */
    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        return jwt;
    }

}
