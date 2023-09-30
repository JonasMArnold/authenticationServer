import com.example.auth.AuthServerApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(classes = AuthServerApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class TestUserRegister {

    @Autowired
    private WebTestClient webTestClient;

    private void sendAndExpect200(String username, String password, String email, String firstName, String lastName) {
        // Send a POST request with form data
        webTestClient.post()
                .uri("/register")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue("username=" + username + "&password=" + password
                        + "&email=" + email + "&firstName=" + firstName + "&lastName=" + lastName)
                .exchange()
                .expectStatus().isOk();
    }

    private void sendAndExpect400(String username, String password, String email, String firstName, String lastName) {
        // Send a POST request with form data
        webTestClient.post()
                .uri("/register")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue("username=" + username + "&password=" + password
                        + "&email=" + email + "&firstName=" + firstName + "&lastName=" + lastName)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    public void testRegistrationOk() {
        String username = "testuser12341234";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "test";

        sendAndExpect200(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationOk2() {
        String username = "testu22ser";
        String password = "AAAAAa1d**+ö";
        String email = "testemail@example.com";
        String firstName = "teadfasdfst";
        String lastName = "teadfst";

        sendAndExpect200(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationTooShort() {
        String username = "u";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "test";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationTooShort2() {
        String username = "ueeee";
        String password = "Passwo1";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "test";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationTooShort3() {
        String username = "user";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "m";
        String lastName = "test";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationTooShort4() {
        String username = "user";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "m";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationTooLong() {
        String username = "user1234123412345";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "test";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationTooLong2() {
        String username = "user";
        String password = "Abc1....1234123412341234123412341234123412341234123412341234" +
                "12341234123412341234123412341234123412341234123412341234123412341234_";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "test";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationTooLong3() {
        String username = "user";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "test12341234123412341234123412345";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationTooLong4() {
        String username = "user";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "test12341234123412341234123412345";
        String lastName = "test";

        sendAndExpect400(username, password, email, firstName, lastName);
    }


    @Test
    public void testRegistrationBadChar() {
        String username = "testu3%ser";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "test";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationBadChar2() {
        String username = "testuser";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "te.st";
        String lastName = "test";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationBadChar3() {
        String username = "testuser";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "tes33t";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

    @Test
    public void testRegistrationBadChar4() {
        String username = "testuser";
        String password = "Testpassword1";
        String email = "testemail@example.com";
        String firstName = "test";
        String lastName = "te st";

        sendAndExpect400(username, password, email, firstName, lastName);
    }

}