package Prova.Security.auth;

import Prova.Security.model.User;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import javax.naming.AuthenticationException;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtil {

    private final String secret_key = "chiaveSegreta";
    private long accessTokenValididity = 60*60*100;

    private final JwtParser jwtParser;

    private final String TOKEN_HEADER = "Autorizzazione";
    private final String TOKEN_PREFIX = "Portatore";

    public JwtUtil() {
        this.jwtParser = Jwts.parser().setSigningKey(secret_key);
    }

    public String createToken (User user){

        Claims claims = Jwts.claims().setSubject(user.getEmail());
        claims.put("firstName",user.getFirstName());
        claims.put("lastName",user.getLastName());
        Date tokenCreateTime = new Date();
        Date tokenValidity = new Date(tokenCreateTime.getTime()+ TimeUnit.MINUTES.toMillis(accessTokenValididity));

        return  Jwts.builder()
                .setClaims(claims)
                .setExpiration(tokenValidity)
                .signWith(SignatureAlgorithm.HS256,secret_key)
                .compact();
    }

    private Claims parseJwtClaims(String token){
        return  jwtParser.parseClaimsJwt(token).getBody();
    }

    private Claims resolveClaims(HttpServletRequest req){
        try{
            String token = resolveToken(req);
            if(token != null){
                return parseJwtClaims(token);
            }
            return  null;
        }catch (ExpiredJwtException ex){
            req.setAttribute("expired",ex.getMessage());
            throw  ex;
        }catch (Exception ex){
            req.setAttribute("invalid",ex.getMessage());
            throw ex;
        }
    }

    public String resolveToken(HttpServletRequest request){
        String bearerToken = request.getHeader(TOKEN_HEADER);
        if(bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)){
            return bearerToken.substring(TOKEN_PREFIX.length());
        }
        return  null;
    }

    public boolean validateClaims(Claims claims) throws AuthenticationException {
        try{
            return  claims.getExpiration().after(new Date());
        }catch (Exception ex){
            throw ex;
        }
    }
    public String getEamil(Claims claims){
        return claims.getSubject();
    }

    private List<String> getRoles(Claims claims){
        return (List<String>) claims.get("roles");
    }

}
