package org.example.testsecurity.provider;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import kr.co.foryousoft.new4ubackend.auth.dto.SignInDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

	private final RedisTemplate<String, String> redisTemplate;

	@Value("${spring.jwt.secret}")
	private String secretKey;

	@Value("${spring.jwt.access-expiration-time}")
	private Long accessExpirationTime;

	@Value("${spring.jwt.refresh-expiration-time}")
	private Long refreshExpirationTime;

	@PostConstruct
	protected void init() {
		secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
	}

	/**
	 * Access 토큰 생성
	 */
	// 로그인 서비스 단에서 createAccessToken, createRefreshToken 호출하고
	// 로그인 시 jwt 필터는 안 타도록
	public String createAccessToken(SignInDto.Request signInDto) {

		Claims claims = Jwts.claims().setSubject(signInDto.getAdmId());

		claims.put("auth", "MASTER ADMIN"); //샘플, 추후 수정

		Date nowDate = new Date();
		Date exDate = new Date(nowDate.getTime() + accessExpirationTime);  // 1시간

		return Jwts.builder()
			.setClaims(claims)  // 사용자 정보
			.setIssuedAt(nowDate)  // 토큰 발급 시간
			.setExpiration(exDate)  // 만료 시간
			.signWith(SignatureAlgorithm.HS256, secretKey)  // 암호화 알고리즘과 비밀 키
			.compact();  // 토큰 생성
	}

	/**
	 * Refresh 토큰 생성
	 */
	public String createRefreshToken(SignInDto.Request signInDto) {

		Claims claims = Jwts.claims().setSubject(signInDto.getAdmId());

		Date nowDate = new Date();
		Date exDate = new Date(nowDate.getTime() + refreshExpirationTime);  // 30일

		String refreshToken = Jwts.builder()
			.setClaims(claims)  // 사용자 정보
			.setIssuedAt(nowDate)  // 토큰 발급 시간
			.setExpiration(exDate)  // 만료 시간
			.signWith(SignatureAlgorithm.HS256, secretKey)  // 암호화 알고리즘과 비밀 키
			.compact();  // 토큰 생성

		// redis에 저장
		redisTemplate.opsForValue().set(
			signInDto.getAdmId(),
			refreshToken,
			refreshExpirationTime,
			TimeUnit.MILLISECONDS
		);

		System.out.println("===토큰 복호화 결과=== " + decodeToken(refreshToken));

		return refreshToken;
	}

	/**
	 * 토큰 복호화
	 */
	public Claims decodeToken(String token) {
		Claims claims = Jwts.parserBuilder()
			.setSigningKey(secretKey)
			.build()
			.parseClaimsJws(token)
			.getBody();

		return claims;
	}

	public String getUsername(String token) {
		Claims claims = Jwts.parser()
			.setSigningKey(secretKey)
			.parseClaimsJws(token)
			.getBody();
		return claims.getSubject();
	}

	// public boolean validateToken(String token) {
	// 	try {
	// 		Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
	// 		return !claims.getBody().getExpiration().before(new Date());
	// 	} catch (Exception e) {
	// 		e.printStackTrace();
	// 		return false;
	// 	}
	// }

	/**
	 * 토큰 유효성 검사
	 */
	public boolean validateToken(String token) {
		try {
			Jws<Claims> claims = Jwts.parserBuilder()
				.setSigningKey(secretKey)
				.build()
				.parseClaimsJws(token);
			return !claims.getBody().getExpiration().before(new Date());
		} catch (SecurityException e) {
			log.debug("리소스에 접근 권한이 없습니다.", e);
			throw new RuntimeException("리소스에 접근 권한이 없습니다.");
		} catch (MalformedJwtException e) {
			log.debug("잘못된 형식이거나 손상된 토큰입니다.", e);
			throw e;
		} catch (ExpiredJwtException e) {
			log.debug("토큰 유효기간이 만료되었습니다.", e);
			throw e;
		} catch (UnsupportedJwtException e) {
			log.debug("잘못된 형식의 JWT 토큰 입니다.", e);
			throw new RuntimeException("잘못된 형식의 JWT 토큰 입니다.");
		} catch (IllegalArgumentException e) {
			log.debug("헤더에 토큰이 비어있습니다.", e);
			throw new RuntimeException("헤더에 토큰이 비어있습니다.");
		}
	}

	public Authentication getAuthentication(String token) {
		Claims claims = decodeToken(token);

		if (claims.get("auth") == null) {
			throw new RuntimeException("권한 정보가 없는 토큰입니다.");
		}

		Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get("auth").toString().split("."))
			.map(SimpleGrantedAuthority::new)
			.collect(Collectors.toList());

		UserDetails principal = new User(claims.getSubject(), "", authorities);
		return new UsernamePasswordAuthenticationToken(principal, "", authorities);
	}

	/**
	 * 헤더에서 토큰 값 가져오는 메서드
	 * */
	public String resolveToken(HttpServletRequest request) {
		String headerAuth = request.getHeader("Authorization");
		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			return headerAuth.substring(7);
		}
		// return null;
		throw new RuntimeException("헤더에 인증정보가 없습니다.");
	}

	/**
	 * 레디스에서 Access 토큰 가져오는 메서드
	 */
	public Object getTokenFromRedis(String admId) {
		return redisTemplate.opsForValue().get(admId);
	}

	/**
	 * 토큰 재발급
	 */
	public String recreateAccessToken(String refreshToken, String admId) {
		try {
			if (refreshToken != null && validateToken(refreshToken)) {
				SignInDto.Request signInDto = SignInDto.Request.builder()
					.admId(admId)
					.build();
				return createAccessToken(signInDto);
			}
		} catch (Exception e) {
			log.debug("리프레쉬 토큰 만료. 재 로그인 요망");
			throw new RuntimeException("모든 토큰이 유효기간 만료되었습니다. 재 로그인 해주세요.");
		}
		return null;
	}

	// // JWT 토큰에서 인증 정보 조회
	// public Authentication getAuthentication(String token) {
	// 	UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
	// 	return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
	// }
	//
	// // 토큰에서 회원 정보 추출
	// public String getUserPk(String token) {
	// 	return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
	// }

	// Jwt 토큰으로 인증 정보를 조회
	// public Authentication getAuthentication(String token) {
	// 	return getAuthentication(token, secretKey);
	// }

	// public Authentication getAuthentication(String token, String secretKey) {
	//
	// 	Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
	//
	// 	long userNo =  Long.parseLong(claims.getSubject());
	// 	String userName = claims.containsKey("userName") ? (String)claims.get("userName") : "";
	// 	Map<String, String> botGroupMap = claims.containsKey("botGroup") ? (Map<String, String>)claims.get("botGroup") : null;
	//
	// 	BotGroupVO botGroup = new BotGroupVO();
	// 	botGroup.setGroupNo(ObjectDataUtil.parseLong(botGroupMap.get("groupNo")));
	//
	// 	AuthAdminUserDetails userDetails = new AuthAdminUserDetails();
	// 	userDetails.setUserNo(userNo);
	// 	userDetails.setUserID((String)claims.get("userId"));
	// 	userDetails.setUserName(userName);
	// 	userDetails.setRole((String)claims.get("role"));
	// 	userDetails.setBotGroup(botGroup);
	// 	userDetails.setAccessToken(token);
	//
	// 	List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
	// 	authorities.add(new SimpleGrantedAuthority((String)claims.get("role")));
	// 	userDetails.setAuthorities(authorities);
	//
	// 	return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
	// }
	//
	// public Integer getUserId(HttpServletRequest req) {
	// 	return getUserId(this.resolveToken(req), secretKey);
	// }
	// public Integer getUserId(String token, String secretKey) {
	// 	Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
	// 	return Integer.parseInt(claims.getSubject());
	// }
	//
	// // Request의 Header에서 token 파싱 : "X-Adm-TOKEN: jwt토큰"
	// public String resolveToken(HttpServletRequest req) {
	// 	return req.getHeader(headerKey);
	// }
	//
	// // Jwt 토큰의 유효성 + 만료일자 확인
	// public boolean validateToken(String token) {
	// 	try {
	// 		Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
	// 		return !claims.getBody().getExpiration().before(new Date());
	// 	} catch (Exception e) {
	// 		return false;
	// 	}
	// }

}
