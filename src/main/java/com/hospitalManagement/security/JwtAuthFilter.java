package com.hospitalManagement.security;

import com.hospitalManagement.entity.User;
import com.hospitalManagement.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private final UserRepository userRepository;
    private final AuthUtil authUtil;
    private final HandlerExceptionResolver handlerExceptionResolver;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            log.info("incoming request: {}", request.getRequestURI());

            final String requestTokenHeader = request.getHeader("Authorization");
            if (requestTokenHeader == null || !requestTokenHeader.startsWith("Bearer")) {
//            if token is null or "Bearer" not at start then
//            filterChain.doFilter() method will move you ahead in filter chain
                filterChain.doFilter(request, response);
                return;
            }

//        token : "Bearer jhbfjwbfw.whhbefwhbfwe.fbwaabf" -> ["Bearer ", "hbfjwbfw.whhbefwhbfwe.fbwaabf"]
            String token = requestTokenHeader.split("Bearer ")[1];

            String username = authUtil.getUsernameFromToken(token);

            if (username != null || SecurityContextHolder.getContext().getAuthentication() == null) {
                User user = userRepository.findByUsername(username).get();
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                        = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
//      save this token in Security Context Holder, as it is valid
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
            filterChain.doFilter(request, response);
        }
        catch(Exception e){
            handlerExceptionResolver.resolveException(request, response, null, e);
        }
    }
}
