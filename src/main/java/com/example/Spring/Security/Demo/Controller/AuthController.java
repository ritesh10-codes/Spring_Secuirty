package com.example.Spring.Security.Demo.Controller;


import com.example.Spring.Security.Demo.Entity.User;
import com.example.Spring.Security.Demo.JWT.JWTUtil;
import com.example.Spring.Security.Demo.Repository.UserRepository;
import com.example.Spring.Security.Demo.RequestDTO.UserRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private UserRepository repo;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest request) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        String token = jwtUtil.generateToken(request.getUsername());
        return ResponseEntity.ok(Collections.singletonMap("token", token));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserRequest request) {
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(new BCryptPasswordEncoder().encode(request.getPassword()));
        repo.save(user);
        return ResponseEntity.ok("User registered");
    }

    @GetMapping("/protected")
    public ResponseEntity<String> getProtected() {
        return ResponseEntity.ok("You accessed protected data!");
    }
}
