package jhopn.spring.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {
    @Autowired
    private SecurityDatabaseService securityDatabaseService;

    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(securityDatabaseService).passwordEncoder(NoOpPasswordEncoder.getInstance());
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/users").hasRole("USERS")
                        .requestMatchers("/managers").hasRole("MANAGERS")
                        .anyRequest().authenticated()
                )
                .httpBasic();
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/public/**");
    }
    /*
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("jhoao")
                .password(passwordEncoder().encode("jhoao"))
                .roles("USER")
                .build();
        UserDetails adm = User.builder()
                .username("adm")
                .password(passwordEncoder().encode("adm"))
                .roles("ADM")
                .build();
        return new InMemoryUserDetailsManager(user, adm);
    }
    */

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
