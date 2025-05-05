package com.springsecurity.payload;

import java.util.List;

public class LoginResponse {
    private String jwt;
    private String username;
    private List<String> role;

    public LoginResponse(String username, List<String> roles, String jwtToken) {
        this.username = username;
        this.role = roles;
        this.jwt = jwtToken;
    }

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

    public List<String> getRole() {
        return role;
    }

    public void setRole(List<String> role) {
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public LoginResponse() {
    }

    public LoginResponse(List<String> role, String username, String jwt) {
        this.role = role;
        this.username = username;
        this.jwt = jwt;
    }
}