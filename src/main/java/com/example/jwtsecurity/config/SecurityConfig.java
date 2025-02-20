package com.example.jwtsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
@Profile("!test")
public class SecurityConfig {

    //Used to load user-specific data (usually from DB) during authentication.
    private final UserDetailsService userDetailsService;
    //Filter that processes and validates JWT tokens.
    private final JwtFilter jwtFilter;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService, JwtFilter jwtFilter) {
        this.userDetailsService = userDetailsService;
        this.jwtFilter = jwtFilter;
    }

    @Bean
    //Password encoder using BCrypt
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                //CSRF protection is disabled
                .csrf(AbstractHttpConfigurer::disable)
                //Authorization access
                .authorizeHttpRequests(request -> request
                        .requestMatchers("register", "login").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated())
                //Basic authentications for tests
                .httpBasic(Customizer.withDefaults())
                //add JWT Filter before the username and password and filter token every request
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                //use the default statement session manager for JWT
                .sessionManagement(Customizer.withDefaults())
                //redirect to login logout after logout
                .logout(logout -> logout.logoutSuccessUrl("/login?logout"))
                .build();
    }

    @Bean
    AuthenticationProvider authenticationProvider() {
        //Authenticates users using UserDetailsService and PasswordEncoder.
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        //Increases strength to 12 level
        authProvider.setPasswordEncoder(new BCryptPasswordEncoder(12));
        //Connects to DB via UserDetailsService to validate user credentials.
        authProvider.setUserDetailsService(userDetailsService);
        return authProvider;
    }

    @Bean
    //Handles the process of authentication. Used when authenticating users programmatically (e.g., during login or JWT token generation).
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

