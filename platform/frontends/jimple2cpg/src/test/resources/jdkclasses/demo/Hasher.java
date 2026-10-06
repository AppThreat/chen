package demo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Collectors;

/** JDK types from java.base: crypto, streams, lambdas and indy string concatenation. */
public class Hasher {
    private final String algorithm;

    public Hasher(String algorithm) {
        this.algorithm = algorithm;
    }

    public byte[] digest(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    public String hex(String input) throws NoSuchAlgorithmException {
        return HexFormat.of().formatHex(digest(input));
    }

    public String describe(List<String> inputs) {
        // invokedynamic: StringConcatFactory and LambdaMetafactory
        return algorithm + ":" + inputs.stream().map(String::toUpperCase).filter(s -> !s.isEmpty())
                .collect(Collectors.joining(","));
    }

    public int readAll(byte[] data) throws IOException {
        try (InputStream in = new ByteArrayInputStream(data)) {
            return in.readAllBytes().length;
        }
    }

    public static void main(String[] args) throws Exception {
        Hasher h = new Hasher("SHA-256");
        System.out.println(h.hex(String.join(" ", args)));
    }
}
