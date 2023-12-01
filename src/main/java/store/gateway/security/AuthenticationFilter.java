package store.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;
import store.auth.AuthController;
import store.auth.IdIn;
import store.auth.IdOut;
import store.gateway.JwtService;

@Component
public class AuthenticationFilter implements GlobalFilter {

    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String HEADER_BEARER = "Bearer";

    @Autowired
    private RouterValidator routerValidator;

    @Autowired
    private AuthController authController;

    @Autowired
    private JwtService jwtService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        if (!routerValidator.isSecured.test(request)) {
            return chain.filter(exchange);
        }
        if (!isAuthMissing(request)) {
            final String[] parts = this.getAuthHeader(request).split(" ");
            if (parts.length != 2 || !parts[0].equals(HEADER_BEARER)) {
                return this.onError(exchange, HttpStatus.FORBIDDEN);                
            }
            final String token = parts[1];
            // authController.login(new LoginIn("gma@espm.br", "123456789"));
            // final IdOut idOut = authController.id(new IdIn(token));
            // if (idOut == null) {
            //     return this.onError(exchange, HttpStatus.FORBIDDEN);                
            // }
            // final String id = idOut.id();
            final String id = jwtService.getId(token);
            this.updateRequest(exchange, id);
            return chain.filter(exchange);
        }
        return this.onError(exchange, HttpStatus.UNAUTHORIZED);
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private String getAuthHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty(HEADER_AUTHORIZATION).get(0);
    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
    }    

    private void updateRequest(ServerWebExchange exchange, String id) {
        exchange.getRequest().mutate()
                .header("id-user", id)
                .build();
    }

}
