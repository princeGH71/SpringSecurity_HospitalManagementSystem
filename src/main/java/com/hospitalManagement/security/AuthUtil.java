package com.hospitalManagement.security;

import com.hospitalManagement.entity.User;
import com.hospitalManagement.entity.type.Auth2ProviderType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
//import java.lang.*;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j
@Component
public class AuthUtil {

//    secrete key
    @Value("${jwt.secretKey}")
    private String jwtSecretKey;

//    Header he ye token ka: we have to convert our secretkey into hmacSha key, iska object hm use krege token bnane k liye
    private SecretKey getSecretKey(){
        return Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));
    }

//    upar ki key se token bnaege ab, User ka object use hoga as payload
    public String generateAccessToken(User user){
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("userId", user.getId())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000*60*10))
                .signWith(getSecretKey())
                .compact();
    }


    public String getUsernameFromToken(String token) {
        Claims claim = Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claim.getSubject();
    }

    public Auth2ProviderType getAuth2ProviderTypeFromRegisterationId(String registerationId){
        return switch (registerationId.toLowerCase()){
            case "google" -> Auth2ProviderType.GOOGLE;
            case "github" -> Auth2ProviderType.GITHUB;
            case "facebook" -> Auth2ProviderType.FACEBOOK;
            default -> throw new IllegalArgumentException("Unsupported OAuth2 provider: "+ registerationId);
        };
    }

    public String determineProviderIdFromOAuth2User(OAuth2User oAuth2User, String registerationId){
//        each OAuth2 provider gives different types of id , so check and create case for it.
        String providerId = switch (registerationId.toLowerCase()){
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("id").toString();
            default -> {
                log.error("Unsupported OAuth2 provider: {}", registerationId);
                throw new IllegalArgumentException("Unsupported OAuth2 provider: "+ registerationId);
            }
        };

        if(providerId == null || providerId.isBlank()){
            log.error("Unable to determine providerId for provider : {}", registerationId);
            throw new IllegalArgumentException("Unable to determine providerId form OAuth2 login");
        }
        return providerId;
    }

//    agar email mil gya to thik vrna, alag alag provider type se unki id nikal k le skte h
    public String determineUsernameFromOAuth2User(OAuth2User oAuth2User, String registerationId, String providerId){
        String email = oAuth2User.getAttribute("email");
        if(email != null && !email.isBlank()){
            return email;
        }
        return switch (registerationId.toLowerCase()){
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("login");
            default -> providerId;
        };
    }
}
