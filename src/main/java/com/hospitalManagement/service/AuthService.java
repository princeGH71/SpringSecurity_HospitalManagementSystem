package com.hospitalManagement.service;

import com.hospitalManagement.dto.LoginRequestDto;
import com.hospitalManagement.dto.LoginResponseDto;
import com.hospitalManagement.dto.SignupResponseDto;
import com.hospitalManagement.entity.User;
import com.hospitalManagement.repository.UserRepository;
import com.hospitalManagement.security.AuthUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final AuthUtil authUtil;

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;
    public ResponseEntity<LoginResponseDto> login(LoginRequestDto loginRequestDto) {
//        idhr hm requestDto se maal leke auth manager ko dege, vo UserDetailsService se DB se authenticate krega,
//        and PasswordEncoder se password encode krega
        System.out.println("1. We reached the Login end point");
        try{
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword()));
                    System.out.println("We passed the authentication");
//        agar authenticate hogya to aage badhege

//        idhr hmko User ka object milega jo authenticate ho chuka he, isko token banne bhej skte h
            User user = (User) authentication.getPrincipal();

            String token = authUtil.generateAccessToken(user);
            return new ResponseEntity<>(new LoginResponseDto(token, user.getId()), HttpStatus.OK);

        }catch(Exception e){
            System.out.println("exception at authentication "+e);
        }

       return null;

    }

    public ResponseEntity<SignupResponseDto> signup(LoginRequestDto signupRequestDto) {
        User user = userRepository.findByUsername(signupRequestDto.getUsername()).orElse(null);

        if(user != null){
            throw new IllegalArgumentException("User already Exists!");
        }

        user = User.builder()
                .username(signupRequestDto.getUsername())
                .password(passwordEncoder.encode(signupRequestDto.getPassword()))
                .build();

        User saved = userRepository.save(user);
        log.info("Saved user id: {}", saved.getId());
        return new ResponseEntity<>(new SignupResponseDto(saved.getId(), saved.getUsername()), HttpStatus.OK);
    }
}
