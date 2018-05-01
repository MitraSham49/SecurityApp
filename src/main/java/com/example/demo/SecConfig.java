package com.example.demo;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration //Add this to indicate that this determines the application's configuration settings
@EnableWebSecurity
public class SecConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected  void configure (HttpSecurity http)throws Exception{
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
    }

     @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        PasswordEncoder encoder = new BCryptPasswordEncoder();
         auth.inMemoryAuthentication().withUser("Jake").password(encoder.encode("pa$$word"))
                 .authorities("ADMIN")
                 .and()
                 .withUser("theuser").password(encoder.encode("pa$$word"))
                 .authorities("ADMIN")
                 .and()
                 .withUser("Alton").password(encoder.encode("pa$$"))
                 .authorities("ADMIN")
                 .and()
                 .passwordEncoder(encoder);


     }

   /* @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //Creates a password encoder that can be used to encode and decode passwords. You can set it up as a bean so that it can be accessed
        //from the Spring context within the application.
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        //This users in-memory authentication. You will need to modify this section AND create additional classes to allow
        //authentication from users in your database

        auth.inMemoryAuthentication().withUser("Jake").password(encoder.encode("pa$$word"))
                .authorities("ADMIN")
                .and()
                .withUser("theuser").password(encoder.encode("pa$$word"))
                .authorities("ADMIN")//This indicates what role the user is logged in with.
                .and()
                .withUser("Alton").password(encoder.encode("pa$$")).authorities("ADMIN")
                .and()
                .passwordEncoder(encoder);
    }
*/
}
