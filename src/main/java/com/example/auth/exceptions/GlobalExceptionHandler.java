package com.example.auth.exceptions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;


@ControllerAdvice
public class GlobalExceptionHandler {


    private String getJsonString(String... messages) {
        ObjectMapper om = new ObjectMapper();
        ObjectNode json = om.createObjectNode();
        ArrayNode msgArray = om.createArrayNode();

        for (String msg : messages) {
            msgArray.add(msg);
        }

        json.set("errors", msgArray);
        return json.toString();
    }

    /**
     * If an invalid object is passed to a handler annotated with @Valid, this exception handler
     * sends a fitting response to the client
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseBody
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public ResponseEntity<String> validationExceptionHandler(MethodArgumentNotValidException exception) {
        var errors = exception.getBindingResult().getFieldErrors();

        if (errors.size() > 0) {
            String[] messages = new String[errors.size()];
            for (int i = 0; i < errors.size(); i++) {
                messages[i] = errors.get(i).getDefaultMessage();
            }

            return ResponseEntity.badRequest().body(getJsonString(messages));

        } else {

            return ResponseEntity.badRequest().body(getJsonString("invalid input"));
        }
    }

    /**
     * Handles user creation exception
     */
    @ExceptionHandler(UserCreationException.class)
    @ResponseBody
    public ResponseEntity<String> userCreationExceptionHandler(UserCreationException exception) {
        return ResponseEntity.internalServerError().body(getJsonString(exception.getMessage()));
    }
}
