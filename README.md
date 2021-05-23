## Protegendo Jakarta EE com Spring Security

# 1. Visão Geral
Neste tutorial rápido, veremos como proteger um aplicativo da web Jakarta EE com Spring Security.

# 2. Dependências Maven
Vamos começar com as dependências do Spring Security necessárias para este tutorial:

```
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-web</artifactId>
    <version>4.2.3.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
    <version>4.2.3.RELEASE</version>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-taglibs</artifactId>
    <version>4.2.3.RELEASE</version>
</dependency>
```

A versão mais recente do Spring Security (no momento em que este tutorial foi escrito) é 4.2.3.RELEASE; como sempre, podemos verificar o Maven Central para obter as versões mais recentes.

# 3. Configuração de Segurança
Em seguida, precisamos definir a configuração de segurança para o aplicativo Jakarta EE existente:

```
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig 
  extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
      throws Exception {
        auth.inMemoryAuthentication()
          .withUser("user1").password("user1Pass").roles("USER")
          .and()
          .withUser("admin").password("adminPass").roles("ADMIN");
    }
}
```

No método configure(), configuramos o AuthenticationManager. Para simplificar, implementamos uma autenticação simples na memória. Os detalhes do usuário são codificados permanentemente.

Isso deve ser usado para prototipagem rápida quando um mecanismo de persistência completo não é necessário.

A seguir, vamos integrar a segurança ao sistema existente adicionando a classe SecurityWebApplicationInitializer:

```
public class SecurityWebApplicationInitializer
  extends AbstractSecurityWebApplicationInitializer {

    public SecurityWebApplicationInitializer() {
        super(SpringSecurityConfig.class);
    }
}
```

Esta classe garantirá que SpringSecurityConfig seja carregado durante a inicialização do aplicativo. Neste estágio, alcançamos uma implementação básica do Spring Security. Com esta implementação, Spring Security exigirá autenticação para todas as solicitações e rotas por padrão.

# 4. Configurando regras de segurança
Podemos personalizar ainda mais o Spring Security substituindo o método configure (HttpSecurity http) de WebSecurityConfigurerAdapter:

```
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
      .csrf().disable()
      .authorizeRequests()
      .antMatchers("/auth/login*").anonymous()
      .anyRequest().authenticated()
      .and()
      .formLogin()
      .loginPage("/auth/login")
      .defaultSuccessUrl("/home", true)
      .failureUrl("/auth/login?error=true")
      .and()
      .logout().logoutSuccessUrl("/auth/login");
}
```

Usando o método antMatchers(), configuramos o Spring Security para permitir acesso anônimo a / auth/login e autenticar qualquer outra solicitação.

### 4.1. Página de login personalizada
Uma página de login personalizada é configurada usando o método formLogin():

```
http.formLogin()
  .loginPage("/auth/login")
```

Se isso não for especificado, Spring Security gera uma página de login padrão em /login:

```
<html>
<head></head>
<body>
<h1>Login</h1>
<form name='f' action="/auth/login" method='POST'>
    <table>
        <tr>
            <td>User:</td>
            <td><input type='text' name='username' value=''></td>
        </tr>
        <tr>
            <td>Password:</td>
            <td><input type='password' name='password'/></td>
        </tr>
        <tr>
            <td><input name="submit" type="submit" 
              value="submit"/></td>
        </tr>
    </table>
</form>
</body>
</html>
```

### 4.2. Página de destino personalizada
Após o login bem-sucedido, o Spring Security redireciona o usuário para a raiz do aplicativo. Podemos substituir isso especificando um URL de sucesso padrão:

```
http.formLogin()
  .defaultSuccessUrl("/home", true)
```

Definindo o parâmetro alwaysUse do método defaultSuccessUrl() como true, um usuário sempre será redirecionado para a página especificada.

Se o parâmetro alwaysUse não for definido ou for definido como false, o usuário será redirecionado para a página anterior que ele tentou acessar antes de ser solicitado para autenticação.

Da mesma forma, também podemos especificar uma página de destino de falha personalizada:

```
http.formLogin()
  .failureUrl("/auth/login?error=true")
```

### 4.3. Autorização
Podemos restringir o acesso a um recurso por função:

```
http.formLogin()
  .antMatchers("/home/admin*").hasRole("ADMIN")
```

Um usuário não administrador receberá um erro de acesso negado se tentar acessar o 
/home/admin endpoint.

Também podemos restringir os dados em uma página JSP com base na função de um usuário. Isso é feito usando a tag ```<security: authorize>```:


```
<security:authorize access="hasRole('ADMIN')">
    This text is only visible to an admin
    <br/>
    <a href="<c:url value="/home/admin" />">Admin Page</a>
    <br/>
</security:authorize>
```

Para usar essa tag, temos que incluir a taglib de tags Spring Security na parte superior da página:

```
<%@ taglib prefix="security" 
  uri="http://www.springframework.org/security/tags" %>
```

# 5. Configuração XML do Spring Security
Até agora, vimos como configurar o Spring Security em Java. Vamos dar uma olhada em uma configuração XML equivalente.

Primeiro, precisamos criar um arquivo security.xml na pasta web/WEB-INF/spring que contém nossas configurações XML. Um exemplo desse arquivo de configuração security.xml está disponível no final do artigo.

Vamos começar configurando o gerenciador de autenticação e o provedor de autenticação. Para simplificar, usamos credenciais de usuário embutidas em código simples:

```
<authentication-manager>
    <authentication-provider>
        <user-service>
            <user name="user" 
              password="user123" 
              authorities="ROLE_USER" />
        </user-service>
    </authentication-provider>
</authentication-manager>
```

O que acabamos de fazer é criar um usuário com nome de usuário, senha e uma função.

Como alternativa, podemos configurar nosso provedor de autenticação com um codificador de senha:

```
<authentication-manager>
    <authentication-provider>
        <password-encoder hash="sha"/>
        <user-service>
            <user name="user"
              password="d7e6351eaa13189a5a3641bab846c8e8c69ba39f" 
              authorities="ROLE_USER" />
        </user-service>
    </authentication-provider>
</authentication-manager>
```

Também podemos especificar uma implementação customizada do UserDetailsService do Spring ou uma fonte de dados como nosso provedor de autenticação. Mais detalhes podem ser encontrados aqui.

Agora que configuramos o gerenciador de autenticação, vamos configurar as regras de segurança e aplicar o controle de acesso:

```
<http auto-config='true' use-expressions="true">
    <form-login default-target-url="/secure.jsp" />
    <intercept-url pattern="/" access="isAnonymous()" />
    <intercept-url pattern="/index.jsp" access="isAnonymous()" />
    <intercept-url pattern="/secure.jsp" access="hasRole('ROLE_USER')" />
</http>
```

No snippet acima, configuramos o HttpSecurity para usar o login do formulário e definimos 
/secure.jsp como a URL de sucesso do login. Concedemos acesso anônimo a /index.jsp e ao caminho “/”. Além disso, especificamos que o acesso a /secure.jsp deve exigir autenticação e um usuário autenticado deve ter, pelo menos, o nível de autoridade ROLE_USER.

Definir o atributo auto-config da tag http como true instrui Spring Security a implementar comportamentos padrão que não temos que substituir na configuração. Portanto, /login e 
/logout serão usados para login e logout do usuário, respectivamente. Uma página de login padrão também é fornecida.

Podemos personalizar ainda mais a tag de login do formulário com páginas personalizadas de login e logout, URLs para lidar com falhas e sucessos de autenticação. O apêndice Security Namespace lista todos os atributos possíveis para as tags form-login (e outras). Alguns IDEs também possibilitam a inspeção clicando em uma tag enquanto pressiona a tecla ctrl.

Finalmente, para que a configuração security.xml seja carregada durante a inicialização do aplicativo, precisamos adicionar as seguintes definições ao nosso web.xml:

```
<context-param>                                                                           
    <param-name>contextConfigLocation</param-name>                                        
    <param-value>                                                                         
      /WEB-INF/spring/*.xml                                                             
    </param-value>                                                                        
</context-param>                                                                          
                                                                                          
<filter>                                                                                  
    <filter-name>springSecurityFilterChain</filter-name>                                  
    <filter-class>
      org.springframework.web.filter.DelegatingFilterProxy</filter-class>     
</filter>                                                                                 
                                                                                          
<filter-mapping>                                                                          
    <filter-name>springSecurityFilterChain</filter-name>                                  
    <url-pattern>/*</url-pattern>                                                         
</filter-mapping>                                                                         
                                                                                          
<listener>                                                                                
    <listener-class>
        org.springframework.web.context.ContextLoaderListener
    </listener-class>
</listener>
```


Observe que tentar usar configurações baseadas em XML e Java no mesmo aplicativo JEE pode causar erros.

# 6. Conclusão
Neste artigo, vimos como proteger um aplicativo Jakarta EE com Spring Security e demonstramos configurações baseadas em Java e em XML.

Também discutimos maneiras de conceder ou revogar acesso a recursos específicos com base na função de um usuário.