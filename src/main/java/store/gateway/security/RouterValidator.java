package store.gateway.security;

import java.util.List;
import java.util.function.Predicate;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class RouterValidator {

        @Value("${api.endpoints.open}}") 
        private List<String> openApiEndpoints;

        public Predicate<ServerHttpRequest> isSecured =
                request -> openApiEndpoints
                        .stream()
                        .noneMatch(uri -> {
                                String[] parts = uri.replaceAll("[^a-zA-Z0-9// ]", "").split(" ");
                                return request.getMethod().toString().equalsIgnoreCase(parts[0])
                                    && request.getURI().getPath().equals(parts[1]);
                        });

}
