package com.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

    @GetMapping("/hello")
    public String greetings() {
        return "Hello World!";
    }

    @PreAuthorize( "hasRole('ADMIN')")
    @GetMapping("/admin")
    public String admin() {
        return "Hello Admin!";
    }

    @PreAuthorize( "hasRole('USER')")
    @GetMapping("/user")
    public String user() {
        return "Hello User!";
    }
}
