package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.ArrayList;
import java.util.List;

/**
 * @author i565244
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(authorize ->
//                        authorize.anyRequest().permitAll()  // Allow all requests without authentication
//                );

//        http.requestMatchers(HttpMethod.GET, new String[]{"/actuator/**"})).hasAuthority("DevOps");

//        http.authorizeHttpRequests(authorize ->
//                authorize.requestMatchers("/common/**").hasAnyAuthority("COMMON")
//                        .anyRequest().authenticated());

        http.formLogin(Customizer.withDefaults())
                .authorizeHttpRequests(urlRegistry ->
                        urlRegistry
                                .requestMatchers("/data/**","/common/**").authenticated()
//                                .requestMatchers("/common/**").authenticated()
                                .anyRequest().authenticated());
//        http.httpBasic();
        http.httpBasic((c) -> {
            BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
            entryPoint.setRealmName("Realm");
            entryPoint.afterPropertiesSet();
            c.authenticationEntryPoint(entryPoint);
        });


        //UserDetailsServiceAutoConfiguration  and authenticationProvider can effect at the same time
        http.authenticationProvider(this.buildAuthenticationProvider());



//        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());

        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.ignoringRequestMatchers("/data/**"));


//        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));



        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
        );
        return http.build();
    }

    private DaoAuthenticationProvider buildAuthenticationProvider() {
        List<UserDetails> userDetails = new ArrayList();
        userDetails.add(User.builder().username("admin").password("{noop}" + "admin").authorities(List.of(new SimpleGrantedAuthority("ADMIN"))).build());
        userDetails.add(User.builder().username("dave").password("{noop}" + "admin").authorities(List.of(new SimpleGrantedAuthority("WRITE"),new SimpleGrantedAuthority("READ"))).build());

        UserDetailsService userDetailsService = new InMemoryUserDetailsManager(userDetails);
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        return authenticationProvider;
    }


    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        // Customize the converter if you need to map roles or authorities
        return converter;
    }

    @Bean
    public GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults(""); // Remove the default "ROLE_" prefix
    }

    @Bean
    public JwtDecoder jwtDecoder() {

        //local save publicKey
//        InputStream inputStream = new ClassPathResource("publicKey.pem").getInputStream();
//        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
//        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
//        RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
//        return NimbusJwtDecoder.withPublicKey(publicKey).build();

        // Use the JWK set URI to create the JwtDecoder
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUrl).build();
    }

    //jku
    private final static String jwkSetUrl = "https://dave-test.cslgduke.com/oauth/token";

//    private final static String jwkSetUrl = "https://dave-test-suu47312.authentication.us21.hana.ondemand.com/token_keys";

}
