package store.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter implements GlobalFilter {

    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String HEADER_BEARER = "Bearer";

    @Autowired
    private RouterValidator routerValidator;

    // @Autowired
    // private AuthController authController;

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
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Authorization header format must be Bearer {token}");
            }
            final String token = parts[1];
            final String id = jwtService.getId(token);
            this.updateRequest(exchange, id);
            return chain.filter(exchange);
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing authorization header");
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
