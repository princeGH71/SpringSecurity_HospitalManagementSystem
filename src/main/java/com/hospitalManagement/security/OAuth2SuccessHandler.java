package com.hospitalManagement.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hospitalManagement.dto.LoginResponseDto;
import com.hospitalManagement.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;
    private final ObjectMapper objectMapper;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = ((OAuth2AuthenticationToken) authentication).getPrincipal();

        String registerationId = token.getAuthorizedClientRegistrationId();

        ResponseEntity<LoginResponseDto> loginResponse = authService.handleOAuth2LoginRequest(oAuth2User, registerationId);

//        ye niche kya kiya kisiko nai pta bs krna h, agar hmko login hneka response user ko return krna h
        response.setStatus(loginResponse.getStatusCode().value());
//        frontend ko json response
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        object mapper loginResponse object ko json m convert krke bhejega
        response.getWriter().write(objectMapper.writeValueAsString(loginResponse.getBody()));
    }
}
