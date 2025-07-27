package ng.unionbank.address_book.controller;

import jakarta.validation.Valid;
import ng.unionbank.address_book.dto.Request.LoginRequest;
import ng.unionbank.address_book.dto.Response.LoginResponse;
import ng.unionbank.address_book.model.User;
import ng.unionbank.address_book.repository.UserRepository;
import ng.unionbank.address_book.security.JwtTokenProvider;
import ng.unionbank.address_book.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthController(UserService userService, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, UserRepository userRepository, JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
    }


    @PostMapping("/login")
    public ResponseEntity login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            // Special case for admin user
            if ("admin".equals(loginRequest.getUsername())) {
                try {
                    Authentication authentication = authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(
                                    loginRequest.getUsername(),
                                    loginRequest.getPassword()
                            )
                    );

                    // Generate JWT token
                    String jwtToken = jwtTokenProvider.generateToken(authentication);

                    // Admin login successful
                    LoginResponse response = new LoginResponse(
                            0L, // Admin ID
                            "admin",
                            "admin@test.com",
                            "Admin login successful",
                            jwtToken
                    );

                    return ResponseEntity.ok(response);
                } catch (BadCredentialsException e) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body("Invalid admin credentials");
                }
            }

            // Regular user login logic
            Optional<User> userOptional = userRepository.findByUsername(loginRequest.getUsername());

            if (userOptional.isEmpty()) {
                System.out.println("User not found in database: " + loginRequest.getUsername());
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("User not found: " + loginRequest.getUsername());
            }

            User user = userOptional.get();

            // Verify password against database hash
            boolean passwordMatches = passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash());
            System.out.println("Password match result: " + passwordMatches);

            if (!passwordMatches) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid credentials");
            }

            // Create authentication token
            List<GrantedAuthority> authorities = Collections.singletonList(
                    new SimpleGrantedAuthority("ROLE_USER")
            );

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    user.getUsername(),
                    null, // Don't include password in token
                    authorities
            );

            // Generate JWT token
            String jwtToken = jwtTokenProvider.generateToken(authentication);

            // Return user information with JWT token
            LoginResponse response = new LoginResponse(
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    "Login Successful",
                    jwtToken
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            System.out.println("Login exception: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred during authentication: " + e.getMessage());
        }
    }

}
