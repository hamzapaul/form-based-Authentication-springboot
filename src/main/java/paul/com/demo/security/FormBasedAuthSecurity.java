package paul.com.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static paul.com.demo.model.UserRole.*;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class FormBasedAuthSecurity {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FormBasedAuthSecurity(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()  //spring default security
                .authorizeHttpRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())   //Role based authentication
                .anyRequest()
                .authenticated()
                .and()
                //login
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true)  //redirect to courses after login
//                .passwordParameter("password")
//                .usernameParameter("username")   
                .and()
                //extends remember-me session (default 2weeks)
                .rememberMe()
                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                .key("secret key")
                .and()
                //logout
                .logout()
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) //delete this line if csrf enable
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .logoutSuccessUrl("/login");
        return http.build();
    }

    //In-Memory Authentication
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails userDetails = User.builder()
                .username("Hamza")
                .password(passwordEncoder.encode("password"))
                .roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails sajid = User.builder()
                .username("Sajid")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMIN.name())   //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails paul = User.builder()
                .username("Paul")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                userDetails,
                sajid,
                paul
        );
    }
}
