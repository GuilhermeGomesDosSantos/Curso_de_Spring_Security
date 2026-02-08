package med.voll.web_application.infra.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class ConfiguracoesSeguranca {

    @Bean
    public SecurityFilterChain filtrosSeguranca (HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .authorizeHttpRequests(req -> {
                        req.requestMatchers("/css/**", "/js/**", "/assets/**").permitAll();
                        req.anyRequest().authenticated();
                    })
                .formLogin(form -> form.loginPage("/login")
                        .defaultSuccessUrl("/",true)
                        .permitAll())
                .logout(logout -> logout
                        .logoutSuccessUrl("/logout?logout")
                        .permitAll())
                .rememberMe(rememberMe -> rememberMe.key("123456")
//                        .alwaysRemember(true)
                        .tokenValiditySeconds(2592000))
                .csrf(Customizer.withDefaults())
                .build();
    }

    @Bean
    public PasswordEncoder codificadorSenha(){
        return new BCryptPasswordEncoder();
    }
}
