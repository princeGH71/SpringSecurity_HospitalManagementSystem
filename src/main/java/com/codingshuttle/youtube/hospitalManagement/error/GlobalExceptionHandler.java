package com.codingshuttle.youtube.hospitalManagement.error;

import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.nio.file.AccessDeniedException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ApiError> handleUsernameNotFoundException(UsernameNotFoundException exc){
        ApiError apiError = new ApiError("Username not found with username: "+ exc.getMessage(), HttpStatus.NOT_FOUND);
        return new ResponseEntity<>(apiError, apiError.getStatusCode());
    }
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiError> handleUsernameNotFoundException(AuthenticationException exc){
        ApiError apiError = new ApiError("Authentication Failed: "+ exc.getMessage(), HttpStatus.UNAUTHORIZED);
        return new ResponseEntity<>(apiError, apiError.getStatusCode());
    }
    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ApiError> handleUsernameNotFoundException(JwtException exc){
        ApiError apiError = new ApiError("Invalid JWT token: "+ exc.getMessage(), HttpStatus.UNAUTHORIZED);
        return new ResponseEntity<>(apiError, apiError.getStatusCode());
    }
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleUsernameNotFoundException(AccessDeniedException exc){
        ApiError apiError = new ApiError("Access Denied: Insufficient permissions: "+ exc.getMessage(), HttpStatus.FORBIDDEN);
        return new ResponseEntity<>(apiError, apiError.getStatusCode());
    }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUsernameNotFoundException(Exception exc){
        ApiError apiError = new ApiError("An unexpected error occurred: "+ exc.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        return new ResponseEntity<>(apiError, apiError.getStatusCode());
    }
}
