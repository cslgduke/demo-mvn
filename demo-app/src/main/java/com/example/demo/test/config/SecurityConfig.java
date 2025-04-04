package com.example.demo.test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;

/**
 * @author i565244
 */
@Configuration
@EnableWebSecurity
//When you use this annotation, it sets up a comprehensive security filter chain
//eg: CsrfFilter,AuthorizationFilter,BasicAuthenticationFilter,SecurityContextPersistenceFilter,LogoutFilter,UsernamePasswordAuthenticationFilter
public class SecurityConfig {

    //by default,see WebSecurityEnablerConfiguration,all the requests will be  authenticated
    //request will receive 401 if not authenticated


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize ->
                        authorize.requestMatchers(HttpMethod.POST,"/common/**").permitAll()
                                .requestMatchers(HttpMethod.GET,"/common/**").permitAll()// Allow all requests with prefix "common" without authentication
//                                .requestMatchers("/data/**").hasAnyAuthority("ADMIN")
                                .anyRequest().authenticated()
                //other requset eg. /data/** will be authenticated , if not authenticated, will receive 403
                );

        http.formLogin(Customizer.withDefaults());
        //enable basic authentication
        http.httpBasic(Customizer.withDefaults());
        //UserDetailsServiceAutoConfiguration  and authenticationProvider can effect at the same time
        http.authenticationProvider(this.buildAuthenticationProvider());

        //by default, csrf is enabled, all post request will be checked
        //disable csrf for all requests , whiteSource scan will alert issue
//        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());

        //disable csrf for specific requests
        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.ignoringRequestMatchers("/common/**"));

        //enable bearer token  BearerTokenAuthenticationFilter
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

//    @Bean
//    public JwtDecoder jwtDecoder() {
//
//        //local save publicKey
////        InputStream inputStream = new ClassPathResource("publicKey.pem").getInputStream();
////        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
////        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
////        RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
////        return NimbusJwtDecoder.withPublicKey(publicKey).build();
//
//        // Use the JWK set URI to create the JwtDecoder
//        return NimbusJwtDecoder.withJwkSetUri(jwkSetUrl).build();
//    }

    //jku
//    private final static String jwkSetUrl = "https://dave-test.cslgduke.com/oauth/token";

    private final static String jwkSetUrl = "https://dave-test-suu47312.authentication.us21.hana.ondemand.com/token_keys";

}
