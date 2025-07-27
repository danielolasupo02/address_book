package ng.unionbank.address_book.dto.Response;

public class LoginResponse {
    private Long id;
    private String username;
    private String email;
    private String message;
    private String token;

    public LoginResponse(Long id, String username, String email, String message, String token) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.message = message;
        this.token = token;
    }

    // Getters
    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getMessage() {
        return message;
    }

    public String getToken() {
        return token;
    }
}
