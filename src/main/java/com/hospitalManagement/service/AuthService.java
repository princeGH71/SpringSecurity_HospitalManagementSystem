package com.hospitalManagement.service;

import com.hospitalManagement.dto.LoginRequestDto;
import com.hospitalManagement.dto.LoginResponseDto;
import com.hospitalManagement.dto.SignupResponseDto;
import com.hospitalManagement.entity.User;
import com.hospitalManagement.entity.type.Auth2ProviderType;
import com.hospitalManagement.repository.UserRepository;
import com.hospitalManagement.security.AuthUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
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

    public User signUpInternal(LoginRequestDto signupRequestDto, Auth2ProviderType auth2ProviderType, String providerId){
        User user = userRepository.findByUsername(signupRequestDto.getUsername()).orElse(null);

        if(user != null){
            throw new IllegalArgumentException("User already Exists!");
        }

        user = User.builder()
                .username(signupRequestDto.getUsername())
                .providerId(providerId)
                .auth2ProviderType(auth2ProviderType)
                .build();

        if(auth2ProviderType == Auth2ProviderType.EMAIL){
            user.setPassword(passwordEncoder.encode(signupRequestDto.getPassword()));
        }

        User saved = userRepository.save(user);
        log.info("Saved user id: {}", saved.getId());
        return saved;
    }

//    login controller
//    when we login thru normal email and password
    public ResponseEntity<SignupResponseDto> signup(LoginRequestDto signupRequestDto) {
        User user = signUpInternal(signupRequestDto, Auth2ProviderType.EMAIL, null);
        return new ResponseEntity<>(new SignupResponseDto(user.getId(), user.getUsername()), HttpStatus.OK);
    }

    @Transactional
    public ResponseEntity<LoginResponseDto> handleOAuth2LoginRequest(OAuth2User oAuth2User, String registerationId) {
        Auth2ProviderType auth2ProviderType = authUtil.getAuth2ProviderTypeFromRegisterationId(registerationId);
        String providerId = authUtil.determineProviderIdFromOAuth2User(oAuth2User, registerationId);

//        agr user already exist krta he Db me to hme mil jaega isse
        User user = userRepository.findByProviderIdAndAuth2ProviderType(providerId,auth2ProviderType).orElse(null);

//        simply took email if oAuth2User has provided it, but this field can be used to find the user in DB
        String email = oAuth2User.getAttribute("email");
//        If User doesn't exist then :
//       username in User can be email, as sometimes provider can provide email, that will be also be unique
//        also agar user pehle google se login hua ho or abi direct login krra ho  email or pwd se
//        or sathme agr email se bhi user exist krra he to hme user ko allow nai krna h, usko prev. provider se login krne bolo
        User emailUser = userRepository.findByUsername(email).orElse(null);
//        from both user and emailUser only one should be not-null

        if(user == null || emailUser == null){
//            signup user and save it, pwd is not required as it signup thru google
            String username = authUtil.determineUsernameFromOAuth2User(oAuth2User, registerationId, providerId);
            user = signUpInternal(new LoginRequestDto(username, null),auth2ProviderType, providerId);
        }
        else if(user != null){
            if(email != null && !email.isBlank() && !email.equals(user.getUsername())){
//                in future agar use allowed fo email access then we need to save this email
                user.setUsername(email);
                userRepository.save(user);
            }
        }
        else{
            throw new BadCredentialsException("this user already exists with provider : "+emailUser.getProviderId());
        }

//        now ab user login krra he to token response me bhejna hoga
        LoginResponseDto loginResponseDto = new LoginResponseDto(authUtil.generateAccessToken(user), user.getId());

        return new ResponseEntity<>(loginResponseDto, HttpStatus.OK);
//        fetch OAuth2 Provider type and Provider Id
//        save the providerType and providerId with user info.
//        cuz we don't want to create dual users if user other day logins with other OAuth2 provider
//        if user has an account : direct login


//        otherwise, first signup and then login

    }
}
